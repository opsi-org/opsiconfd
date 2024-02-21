#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

# pylint: disable=invalid-name
"""
opsiconfd backend performance tests
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from asyncio import create_task, get_event_loop
from urllib.parse import urlparse

import aiohttp
import lz4.frame  # type: ignore[import]
from opsicommon.messagebus import (  # type: ignore[import]
	ChannelSubscriptionRequestMessage,
	EventMessage,
	Message,
)


class MessagebusClient:  # pylint: disable=too-many-instance-attributes
	def __init__(self, test_manager: TestManager, name: str, start_wait: int = 0) -> None:
		self.test_manager = test_manager
		self.name = name
		self.start_wait = start_wait
		self.loop: asyncio.AbstractEventLoop | None = None
		self.session: aiohttp.ClientSession | None = None
		self.websocket: aiohttp.ClientWebSocketResponse | None = None
		self.should_exit = asyncio.Event()
		self.messages_in = 0
		self.messages_out = 0
		self.exception: Exception | None = None

	async def websocket_reader(self) -> None:
		try:
			if not self.websocket:
				raise RuntimeError("Websocket not connected")
			while not self.should_exit.is_set():
				msg = await self.websocket.receive()
				if msg.type == aiohttp.WSMsgType.BINARY:
					data = lz4.frame.decompress(msg.data)
					Message.from_msgpack(data)
					self.messages_in += 1
					print(".", end="", flush=True)
				else:
					if self.should_exit.is_set():
						return
					raise RuntimeError(f"Unexpected message type: {msg.type}")
		except Exception as err:  # pylint: disable=broad-except
			print(f"Exception in {self.name}: {err}")
			self.exception = err
			self.should_exit.set()

	async def event_sender(self) -> None:
		try:
			while not self.should_exit.is_set():
				for _ in range(self.test_manager.args.event_interval):
					await asyncio.sleep(1)
					if self.should_exit.is_set():
						return
				await self.send_message(EventMessage(sender="@", event="test", channel="event:test", data={"test": "testdata"}))
		except Exception as err:  # pylint: disable=broad-except
			print(f"Exception in {self.name}: {err}")
			self.exception = err
			self.should_exit.set()

	async def send_message(self, message: Message) -> None:
		if not self.websocket:
			raise RuntimeError("Websocket not connected")
		data = message.to_msgpack()
		data = lz4.frame.compress(data)
		await self.websocket.send_bytes(data)
		self.messages_out += 1

	async def run(self) -> None:
		if self.start_wait > 0:
			await asyncio.sleep(self.start_wait / 1000)
		self.loop = get_event_loop()
		try:
			self.session = aiohttp.ClientSession(
				connector=aiohttp.TCPConnector(ssl=False),
				auth=aiohttp.BasicAuth(login=self.test_manager.args.username, password=self.test_manager.args.password),
			)
			self.websocket = await self.session.ws_connect(url=self.test_manager.args.messagebus_url, params={"compression": "lz4"})

			self.test_manager.add_client_connected()
			create_task(self.websocket_reader())
			await self.send_message(ChannelSubscriptionRequestMessage(sender="@", channel="service:messagebus", channels=["event:test"]))

			if self.test_manager.args.event_interval > 0:
				create_task(self.event_sender())

			while not self.test_manager.all_connected.is_set():
				if self.should_exit.is_set():
					return
				await asyncio.sleep(1)

			if not self.test_manager.args.hold_connection:
				return

			end_time = time.time() + self.test_manager.args.hold_connection
			while time.time() < end_time:
				if self.should_exit.is_set():
					return
				await asyncio.sleep(1)
		except Exception as err:  # pylint: disable=broad-except
			print(f"Exception in {self.name}: {err}")
			self.exception = err
		finally:
			self.should_exit.set()
			if self.websocket:
				await self.websocket.close()
			if self.session:
				await self.session.close()
			self.test_manager.remove_client_connected()


class TestManager:  # pylint: disable=too-few-public-methods
	def __init__(self) -> None:
		arg_parser = argparse.ArgumentParser()
		arg_parser.add_argument("--server", action="store", type=str, help="Configserver url / address", default="https://localhost:4447")
		arg_parser.add_argument("--username", action="store", type=str, help="Auth username", default="adminuser")
		arg_parser.add_argument("--password", action="store", type=str, help="Auth password", default="adminuser")
		arg_parser.add_argument("--clients", action="store", type=int, help="Number of clients", default=1)
		arg_parser.add_argument(
			"--event-interval", action="store", type=int, help="Have the clients send events at this interval (in seconds)", default=30
		)
		arg_parser.add_argument(
			"--hold-connection",
			type=int,
			help="Hold client connection for this long after all clients are connected (in seconds)",
			default=0,
		)
		arg_parser.add_argument("--start-gap", action="store", type=int, help="Gap in milliseconds between client startup", default=0)
		arg_parser.add_argument("--verbose", action="store_true", help="Verbose output")
		self.args = arg_parser.parse_args()
		url = urlparse(self.args.server)
		base_url = f"{url.scheme or 'https'}://{url.hostname}:{url.port or 4447}"
		self.args.messagebus_url = f"{base_url}/messagebus/v1"
		self.clients_connected = 0
		self.clients_completed = 0
		self.all_connected = asyncio.Event()

	def add_client_connected(self) -> None:
		self.clients_connected += 1
		print("+", end="", flush=True)
		if self.args.verbose:
			print(self.clients_connected)
		if self.clients_connected == self.args.clients:
			self.all_connected.set()

	def remove_client_connected(self) -> None:
		self.clients_connected -= 1
		print("-", end="", flush=True)
		if self.args.verbose:
			print(self.clients_connected)

	async def main(self) -> None:
		test_clients = [
			MessagebusClient(self, name=f"messagebus client{c+1}", start_wait=c * self.args.start_gap) for c in range(self.args.clients)
		]
		await asyncio.gather(*[client.run() for client in test_clients])
		out = sum([client.messages_out for client in test_clients])  # pylint: disable=consider-using-generator
		_in = sum([client.messages_in for client in test_clients])  # pylint: disable=consider-using-generator
		print(f"\nMessages out={out}, in={_in}")
		exceptions = [client.exception for client in test_clients if client.exception]
		if exceptions:
			print(f"{len(exceptions)} exceptions occurred")
			sys.exit(1)


if __name__ == "__main__":
	asyncio.run(TestManager().main())
