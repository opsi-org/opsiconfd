# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application.teminal
"""

from __future__ import annotations

import os
from asyncio import get_running_loop
from os import getuid
from pathlib import Path
from pwd import getpwuid
from queue import Empty, Queue
from time import time
from typing import Callable

from opsicommon.client.opsiservice import MessagebusListener
from opsicommon.messagebus import (  # type: ignore[import]
	CONNECTION_USER_CHANNEL,
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionRequestMessage,
	FileChunkMessage,
	FileUploadRequestMessage,
	Message,
	TerminalCloseEventMessage,
	TerminalCloseRequestMessage,
	TerminalDataReadMessage,
	TerminalDataWriteMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
	TerminalResizeEventMessage,
	TerminalResizeRequestMessage,
)
from pexpect import spawn  # type: ignore[import]
from pexpect.exceptions import EOF, TIMEOUT  # type: ignore[import]
from psutil import AccessDenied, NoSuchProcess, Process
from starlette.concurrency import run_in_threadpool

from opsiconfd.backend import get_service_client
from opsiconfd.config import config, get_depotserver_id, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import asyncio_create_task

from . import get_messagebus_worker_id, terminals
from .filetransfer import process_message as process_file_message
from .redis import ConsumerGroupMessageReader, MessageReader
from .redis import send_message as redis_send_message

PTY_READER_BLOCK_SIZE = 16 * 1024

terminal_instance_reader = None  # pylint: disable=invalid-name
terminal_request_reader = None  # pylint: disable=invalid-name


async def async_terminal_startup() -> None:
	if "terminal" not in config.disabled_features:
		asyncio_create_task(messagebus_terminal_open_request_worker())
		asyncio_create_task(messagebus_terminal_instance_worker())


async def async_terminal_shutdown() -> None:
	for terminal in list(terminals.values()):
		await terminal.close()
	if terminal_request_reader:
		await terminal_request_reader.stop()
	if terminal_instance_reader:
		await terminal_instance_reader.stop()


def start_pty(shell: str, rows: int | None = 30, cols: int | None = 120, cwd: str | None = None) -> spawn:
	rows = rows or 30
	cols = cols or 120
	sp_env = os.environ.copy()
	sp_env.update({"TERM": "xterm-256color"})
	logger.info("Starting new pty with shell %r, rows %r, cols %r, cwd %r", shell, rows, cols, cwd)
	return spawn(shell, dimensions=(rows, cols), env=sp_env, cwd=cwd)


class Terminal:  # pylint: disable=too-many-instance-attributes
	default_rows = 30
	max_rows = 100
	default_cols = 120
	max_cols = 300
	idle_timeout = 8 * 3600

	def __init__(self, terminal_open_request: TerminalOpenRequestMessage, sender: str, send_message: Callable) -> None:  # pylint: disable=too-many-arguments
		self._terminal_open_request = terminal_open_request
		self._sender = sender
		self._send_message = send_message
		self._last_usage = time()
		self._loop = get_running_loop()
		self._cwd = getpwuid(getuid()).pw_dir
		self._pty: spawn | None = None
		self._closing = False
		self.set_size(terminal_open_request.rows, terminal_open_request.cols, False)
		self._loop.create_task(self.start())

	@property
	def terminal_id(self) -> str:
		return self._terminal_open_request.terminal_id

	async def start(self) -> None:
		self._pty = await self._loop.run_in_executor(
			None,
			start_pty,
			self._terminal_open_request.shell or config.admin_interface_terminal_shell,
			self.rows,
			self.cols,
			self._cwd,
		)
		logger.debug("pty started")
		self._pty_reader_task = self._loop.create_task(self._pty_reader())

	def back_channel(self, message: Message | None = None) -> str:
		if message and message.back_channel:
			return message.back_channel
		return self._terminal_open_request.response_channel

	def set_size(self, rows: int | None = None, cols: int | None = None, pty_set_size: bool = True) -> None:
		self.rows = min(max(1, int(rows or self.default_rows)), self.max_rows)
		self.cols = min(max(1, int(cols or self.default_cols)), self.max_cols)
		if pty_set_size and self._pty:
			self._pty.setwinsize(self.rows, self.cols)

	def get_cwd(self) -> Path | None:
		if not self._pty:
			return None
		try:
			proc = Process(self._pty.pid)
		except (NoSuchProcess, ValueError):
			return None

		cwd = proc.cwd()
		for child in proc.children(recursive=True):
			try:
				cwd = child.cwd()
			except AccessDenied:
				# Child owned by an other user (su)
				pass
		return Path(cwd)

	async def _pty_reader(self) -> None:
		pty_reader_block_size = PTY_READER_BLOCK_SIZE
		try:
			while self._pty and not self._closing:
				try:
					logger.trace("Read from pty")
					data = await self._loop.run_in_executor(None, self._pty.read_nonblocking, pty_reader_block_size, 1.0)
					logger.trace(data)
					self._last_usage = time()
					message = TerminalDataReadMessage(
						sender=self._sender, channel=self.back_channel(), terminal_id=self.terminal_id, data=data
					)
					await self._send_message(message)
				except TIMEOUT:
					if time() > self._last_usage + self.idle_timeout:
						logger.notice("Terminal %r timed out", self.terminal_id)
						await self.close()
		except EOF:
			# shell exit
			await self.close()
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
			await self.close()

	async def process_message(self, message: TerminalDataWriteMessage | TerminalResizeRequestMessage | TerminalCloseRequestMessage) -> None:
		if isinstance(message, TerminalDataWriteMessage):
			# Do not wait for completion to minimize rtt
			if not self._closing and self._pty:
				self._loop.run_in_executor(None, self._pty.write, message.data)
		elif isinstance(message, TerminalResizeRequestMessage):
			self.set_size(message.rows, message.cols)
			res_message = TerminalResizeEventMessage(
				sender=self._sender,
				channel=self.back_channel(message),
				ref_id=message.id,
				terminal_id=self.terminal_id,
				rows=self.rows,
				cols=self.cols,
			)
			await self._send_message(res_message)
		elif isinstance(message, TerminalCloseRequestMessage):
			await self.close()
		else:
			logger.warning("Received invalid message type %r", message.type)

	async def close(self, message: TerminalCloseRequestMessage | None = None) -> None:
		if self._closing:
			return
		logger.info("Close terminal")
		self._closing = True
		try:
			res_message = TerminalCloseEventMessage(
				sender=self._sender,
				channel=self.back_channel(message),
				ref_id=message.id if message else None,
				terminal_id=self.terminal_id,
			)
			await self._send_message(res_message)
			if self.terminal_id in terminals:
				del terminals[self.terminal_id]
			if self._pty:
				self._pty.close(True)
			if self._pty_reader_task:
				self._pty_reader_task.cancel()
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)


async def _process_message(
	message: TerminalOpenRequestMessage | TerminalDataWriteMessage | TerminalResizeRequestMessage | TerminalCloseRequestMessage,
	send_message: Callable,
) -> None:
	terminal = terminals.get(message.terminal_id)

	try:
		if isinstance(message, TerminalOpenRequestMessage):
			if not terminal:
				terminal = Terminal(terminal_open_request=message, sender=get_messagebus_worker_id(), send_message=send_message)
				terminals[message.terminal_id] = terminal
			else:
				# Resize to redraw screen
				terminal.set_size(terminal.rows - 1, terminal.cols)
				terminal.set_size(terminal.rows, terminal.cols)
			open_event = TerminalOpenEventMessage(
				sender=get_messagebus_worker_id(),
				channel=terminal.back_channel(message),
				ref_id=message.id,
				terminal_id=message.terminal_id,
				back_channel=f"{get_messagebus_worker_id()}:terminal",
				rows=terminal.rows,
				cols=terminal.cols,
			)
			await send_message(open_event)
		elif terminal:
			await terminal.process_message(message)
		else:
			raise RuntimeError("Invalid terminal id")
	except Exception as err:  # pylint: disable=broad-except
		logger.warning(err, exc_info=True)
		if terminal:
			await terminal.close()
		else:
			close_event = TerminalCloseEventMessage(
				sender=get_messagebus_worker_id(), channel=message.back_channel or message.sender, terminal_id=message.terminal_id
			)
			await send_message(close_event)


async def messagebus_terminal_instance_worker_configserver() -> None:
	global terminal_instance_reader  # pylint: disable=invalid-name,global-statement

	channel = f"{get_messagebus_worker_id()}:terminal"
	terminal_instance_reader = MessageReader(channels={channel: "$"})
	async for _redis_id, message, _context in terminal_instance_reader.get_messages():
		try:
			if isinstance(
				message, (TerminalDataWriteMessage, TerminalResizeRequestMessage, TerminalOpenRequestMessage, TerminalCloseRequestMessage)
			):
				await _process_message(message, redis_send_message)
			elif isinstance(message, (FileChunkMessage, FileUploadRequestMessage)):
				await process_file_message(message, redis_send_message)
			else:
				raise ValueError(f"Received invalid message type {message.type}")
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)


async def messagebus_terminal_instance_worker_depotserver() -> None:
	channel = f"{get_messagebus_worker_id()}:terminal"

	service_client = await run_in_threadpool(get_service_client, "messagebus terminal")
	subscription_message = ChannelSubscriptionRequestMessage(
		sender=CONNECTION_USER_CHANNEL, channel="service:messagebus", channels=[channel], operation="add"
	)
	await service_client.messagebus.async_send_message(subscription_message)

	message_queue: Queue[
		TerminalDataWriteMessage
		| TerminalResizeRequestMessage
		| TerminalOpenRequestMessage
		| TerminalCloseRequestMessage
		| FileChunkMessage
		| FileUploadRequestMessage
	] = Queue()

	class TerminalMessageListener(MessagebusListener):
		def message_received(self, message: Message) -> None:
			try:
				if isinstance(
					message,
					(
						TerminalDataWriteMessage,
						TerminalResizeRequestMessage,
						TerminalOpenRequestMessage,
						TerminalCloseRequestMessage,
						FileChunkMessage,
						FileUploadRequestMessage,
					),
				):
					message_queue.put(message, block=True)
				elif isinstance(message, ChannelSubscriptionEventMessage):
					pass
				else:
					raise ValueError(f"Received invalid message type {message.type}")
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)

	listener = TerminalMessageListener()

	service_client.messagebus.register_messagebus_listener(listener)
	while True:
		try:
			try:
				message = await run_in_threadpool(message_queue.get, block=True, timeout=1.0)
			except Empty:
				continue
			if isinstance(message, (FileChunkMessage, FileUploadRequestMessage)):
				await process_file_message(message, service_client.messagebus.async_send_message)
			else:
				await _process_message(message, service_client.messagebus.async_send_message)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)


async def messagebus_terminal_instance_worker() -> None:
	if opsi_config.get("host", "server-role") == "configserver":
		await messagebus_terminal_instance_worker_configserver()
	elif opsi_config.get("host", "server-role") == "depotserver":
		await messagebus_terminal_instance_worker_depotserver()


async def messagebus_terminal_open_request_worker_configserver() -> None:
	global terminal_request_reader  # pylint: disable=invalid-name,global-statement

	channel = "service:config:terminal"

	# ID "0" means: Start reading pending messages (not ACKed) and continue reading new messages
	terminal_request_reader = ConsumerGroupMessageReader(
		consumer_group=channel,
		consumer_name=get_messagebus_worker_id(),
		channels={channel: "0"},
	)
	async for redis_id, message, _context in terminal_request_reader.get_messages():
		try:
			if isinstance(message, TerminalOpenRequestMessage):
				await _process_message(message, redis_send_message)
			else:
				raise ValueError(f"Received invalid message type {message.type}")
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
		# ACK Message
		await terminal_request_reader.ack_message(message.channel, redis_id)


async def messagebus_terminal_open_request_worker_depotserver() -> None:
	depot_id = get_depotserver_id()
	service_client = await run_in_threadpool(get_service_client, "messagebus terminal")
	message = ChannelSubscriptionRequestMessage(
		sender=CONNECTION_USER_CHANNEL, channel="service:messagebus", channels=[f"service:depot:{depot_id}:terminal"], operation="set"
	)
	await service_client.messagebus.async_send_message(message)

	message_queue: Queue[TerminalOpenRequestMessage] = Queue()

	class TerminalOpenRequestMessageListener(MessagebusListener):
		def message_received(self, message: Message) -> None:
			if isinstance(message, TerminalOpenRequestMessage):
				message_queue.put(message, block=True)

	listener = TerminalOpenRequestMessageListener()

	service_client.messagebus.register_messagebus_listener(listener)
	while True:
		try:
			term_message: TerminalOpenRequestMessage = await run_in_threadpool(message_queue.get, block=True, timeout=1.0)
		except Empty:
			continue
		await _process_message(term_message, service_client.messagebus.async_send_message)


async def messagebus_terminal_open_request_worker() -> None:
	if opsi_config.get("host", "server-role") == "configserver":
		await messagebus_terminal_open_request_worker_configserver()
	elif opsi_config.get("host", "server-role") == "depotserver":
		await messagebus_terminal_open_request_worker_depotserver()
