#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

# pylint: disable=invalid-name
"""
opsiconfd backend performance tests
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import re
from asyncio import create_task, get_event_loop, sleep
from datetime import datetime
from statistics import mean, median
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from uuid import uuid4

import aiohttp
import lz4.frame  # type: ignore[import]
from opsicommon.messagebus.message import (
	Message,
	TerminalCloseRequestMessage,
	TerminalDataReadMessage,
	TerminalDataWriteMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
)

CHANNEL = "service:config:terminal"


def decompress_data(data: bytes, compression: str) -> bytes:
	if compression == "lz4":
		return lz4.frame.decompress(data)
	if compression == "gzip":
		return gzip.decompress(data)
	raise ValueError(f"Unhandled compression {compression!r}")


def compress_data(data: bytes, compression: str, compression_level: int = 0, lz4_block_linked: bool = True) -> bytes:
	if compression == "lz4":
		return lz4.frame.compress(data, compression_level=compression_level, block_linked=lz4_block_linked)
	if compression == "gzip":
		return gzip.compress(data)
	raise ValueError(f"Unhandled compression {compression!r}")


class TerminalClient:
	def __init__(self, test_manager: TestManager, name: str) -> None:
		self.test_manager = test_manager
		self.name = name
		self.loop: Optional[asyncio.AbstractEventLoop] = None
		self.session: Optional[aiohttp.ClientSession] = None
		self.websocket: Optional[aiohttp.ClientWebSocketResponse] = None
		self.websocket_reader_task: Optional[asyncio.Task] = None
		self.websocker_writer_task: Optional[asyncio.Task] = None
		self.terminal_id = str(uuid4())
		self.back_channel: str | None = None
		self.should_exit = False
		self.received_nums: Set[int] = set()
		self.time_started: Optional[datetime] = None
		self.time_ended: Optional[datetime] = None

	async def websocker_writer(self) -> None:
		for num in range(self.test_manager.args.commands):
			assert self.back_channel
			msg = TerminalDataWriteMessage(
				sender="*",
				channel=self.back_channel,
				terminal_id=self.terminal_id,
				data=f"###{num+1}###\r".encode("utf-8"),
			)
			await self.send_message(msg)

	async def websocket_reader(self) -> None:
		if not self.websocket:
			raise RuntimeError("Websocket not connected")
		while not self.should_exit:
			msg = await self.websocket.receive()
			data = msg.data
			if self.test_manager.args.compression:
				data = decompress_data(data, self.test_manager.args.compression)
			message = Message.from_msgpack(data)

			if not hasattr(message, "terminal_id") or message.terminal_id != self.terminal_id:
				continue

			if isinstance(message, TerminalOpenEventMessage):
				self.back_channel = message.back_channel
			elif isinstance(message, TerminalDataReadMessage):
				for match in re.findall(
					r"###(\d+)###",
					message.data.decode("utf-8"),
				):
					self.received_nums.add(int(match))
				if len(self.received_nums) == self.test_manager.args.commands:
					self.time_ended = datetime.utcnow()
					self.should_exit = True

	async def send_message(self, message: Message) -> None:
		if not self.websocket:
			raise RuntimeError("Websocket not connected")
		data = message.to_msgpack()
		if self.test_manager.args.compression:
			data = compress_data(data, self.test_manager.args.compression)
		await self.websocket.send_bytes(data)

	async def run(self) -> None:
		self.time_started = datetime.utcnow()
		self.websocker_writer_task = create_task(self.websocker_writer())
		while not self.should_exit:
			await sleep(0.5)

	async def setup(self) -> None:
		self.loop = get_event_loop()
		self.session = aiohttp.ClientSession(
			connector=aiohttp.TCPConnector(ssl=False),
			auth=aiohttp.BasicAuth(login=self.test_manager.args.username, password=self.test_manager.args.password),
		)
		self.websocket = await self.session.ws_connect(
			url=self.test_manager.args.messagebus_url, params={"compression": self.test_manager.args.compression or ""}
		)
		self.websocket_reader_task = create_task(self.websocket_reader())
		await self.send_message(TerminalOpenRequestMessage(sender="@", channel=CHANNEL, terminal_id=self.terminal_id, rows=30, cols=120))
		while not self.back_channel:
			await sleep(0.1)

	async def teardown(self) -> None:
		if self.websocket and self.back_channel:
			await self.send_message(TerminalCloseRequestMessage(sender="*", channel=self.back_channel, terminal_id=self.terminal_id))
		if self.websocker_writer_task:
			self.websocker_writer_task.cancel()
		if self.websocket_reader_task:
			self.websocket_reader_task.cancel()
		if self.websocket:
			await self.websocket.close()
		if self.session:
			await self.session.close()


class TestManager:
	def __init__(self) -> None:
		arg_parser = argparse.ArgumentParser()
		arg_parser.add_argument("--server", action="store", type=str, help="Configserver url / address", default="https://localhost:4447")
		arg_parser.add_argument("--username", action="store", type=str, help="Auth username", default="adminuser")
		arg_parser.add_argument("--password", action="store", type=str, help="Auth password", default="adminuser")
		arg_parser.add_argument("--clients", action="store", type=int, help="Number of clients", default=1)
		arg_parser.add_argument("--commands", action="store", type=int, help="Number of commands to write", default=100)
		arg_parser.add_argument("--compression", action="store", type=str, help="Compression to use (lz4/gzip)", default="")
		arg_parser.add_argument("--iterations", action="store", type=int, help="Number of test repetitions", default=3)
		self.args = arg_parser.parse_args()
		url = urlparse(self.args.server)
		base_url = f"{url.scheme or 'https'}://{url.hostname}:{url.port or 4447}"
		self.args.messagebus_url = f"{base_url}/messagebus/v1"
		# self.args.metrics_url = f"{base_url}/metrics/grafana"
		self.request_stats: List[float] = []

	async def run_test(self) -> Dict[str, int]:
		self.request_stats = []
		test_clients = [TerminalClient(self, name=f"terminal client{c+1}") for c in range(self.args.clients)]
		await asyncio.gather(*[client.setup() for client in test_clients])

		start = datetime.utcnow()
		await asyncio.gather(*[client.run() for client in test_clients])
		end = datetime.utcnow()

		await asyncio.gather(*[client.teardown() for client in test_clients])

		seconds = [
			(client.time_ended - client.time_started).total_seconds() if client.time_ended and client.time_started else 0
			for client in test_clients
		]
		return {
			"per_second": round(mean([self.args.commands / s for s in seconds])),
			"mean": round(mean(seconds) * 1000),
			"median": round(median(seconds) * 1000),
			"real": round((end - start).total_seconds() * 1000),
		}

	async def main(self) -> None:
		stats = []
		for num in range(1, self.args.iterations + 1):
			stats.append(await self.run_test())
			if num < self.args.iterations:
				await sleep(5)

		avg_stats = {key: round(mean([s[key] for s in stats])) for key in list(stats[0])}

		print("statistics (ms):")
		for k, v in avg_stats.items():
			print(f"{k}={v}")


if __name__ == "__main__":
	asyncio.run(TestManager().main())
