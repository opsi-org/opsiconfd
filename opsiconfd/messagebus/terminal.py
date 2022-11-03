# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application.teminal
"""

from __future__ import annotations

import asyncio
from asyncio import get_running_loop
from os import getuid
from pathlib import Path
from pwd import getpwuid
from time import time
from typing import Optional

from OPSI.System import get_subprocess_environment  # type: ignore[import]
from opsicommon.messagebus import (  # type: ignore[import]
	Message,
	MessageType,
	TerminalCloseEvent,
	TerminalDataRead,
	TerminalOpenEvent,
	TerminalOpenRequest,
	TerminalResizeEvent,
)
from pexpect import spawn  # type: ignore[import]
from pexpect.exceptions import EOF, TIMEOUT  # type: ignore[import]
from psutil import AccessDenied, NoSuchProcess, Process  # type: ignore[import]

from ..config import config
from ..logging import logger
from . import get_messagebus_worker_id, terminals
from .filetransfer import process_message as process_file_message
from .redis import ConsumerGroupMessageReader, MessageReader, send_message

PTY_READER_BLOCK_SIZE = 16 * 1024


_messagebus_terminal_request_worker_task = None  # pylint: disable=invalid-name


async def async_terminal_startup() -> None:
	global _messagebus_terminal_request_worker_task  # pylint: disable=invalid-name,global-statement
	if "terminal" not in config.admin_interface_disabled_features:
		_messagebus_terminal_request_worker_task = asyncio.create_task(messagebus_terminal_request_worker())


async def async_terminal_shutdown() -> None:
	if _messagebus_terminal_request_worker_task:
		_messagebus_terminal_request_worker_task.cancel()


def start_pty(shell: str, rows: int | None = 30, cols: int | None = 120, cwd: str | None = None) -> spawn:
	rows = rows or 30
	cols = cols or 120
	sp_env = get_subprocess_environment()
	sp_env.update({"TERM": "xterm-256color"})
	return spawn(shell, dimensions=(rows, cols), env=sp_env, cwd=cwd)


class Terminal:  # pylint: disable=too-many-instance-attributes
	default_rows = 30
	max_rows = 100
	default_cols = 120
	max_cols = 300
	idle_timeout = 600

	def __init__(self, terminal_open_request: TerminalOpenRequest, sender: str) -> None:  # pylint: disable=too-many-arguments
		self._terminal_open_request = terminal_open_request
		self._sender = sender
		self._last_usage = time()
		self._loop = get_running_loop()

		self.set_size(terminal_open_request.rows, terminal_open_request.cols, False)

		cwd = getpwuid(getuid()).pw_dir
		self._pty = start_pty(shell=config.admin_interface_terminal_shell, rows=self.rows, cols=self.cols, cwd=cwd)
		self._pty_reader_task = self._loop.create_task(self._pty_reader())
		self._closing = False

	@property
	def terminal_id(self) -> str:
		return self._terminal_open_request.terminal_id

	@property
	def back_channel(self) -> str:
		return self._terminal_open_request.back_channel

	def set_size(self, rows: int = None, cols: int = None, pty_set_size: bool = True) -> None:
		self.rows = min(max(1, int(rows or self.default_rows)), self.max_rows)
		self.cols = min(max(1, int(cols or self.default_cols)), self.max_cols)
		if pty_set_size:
			self._pty.setwinsize(self.rows, self.cols)

	def get_cwd(self) -> Optional[Path]:
		try:
			proc = Process(self._pty.pid)
		except (NoSuchProcess, ValueError):
			return None

		cwd = proc.cwd()
		for child in proc.children(recursive=True):
			try:  # pylint: disable=loop-try-except-usage
				cwd = child.cwd()
			except AccessDenied:  # pylint: disable=loop-invariant-statement
				# Child owned by an other user (su)
				pass
		return Path(cwd)

	async def _pty_reader(self) -> None:
		pty_reader_block_size = PTY_READER_BLOCK_SIZE
		try:
			while self._pty and not self._closing:
				try:  # pylint: disable=loop-try-except-usage
					logger.trace("Read from pty")
					data = await self._loop.run_in_executor(  # pylint: disable=loop-invariant-statement
						None, self._pty.read_nonblocking, pty_reader_block_size, 1.0
					)
					logger.trace(data)
					self._last_usage = time()
					message = TerminalDataRead(sender=self._sender, channel=self.back_channel, terminal_id=self.terminal_id, data=data)
					await send_message(message)
				except TIMEOUT:  # pylint: disable=loop-invariant-statement
					if time() > self._last_usage + self.idle_timeout:
						logger.notice("Terminal timed out")
						await self.close()
		except EOF:
			# shell exit
			await self.close()
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
			await self.close()

	async def process_message(self, message: Message) -> None:
		if message.type == MessageType.TERMINAL_DATA_WRITE:
			# Do not wait for completion to minimize rtt
			if not self._closing:
				self._loop.run_in_executor(None, self._pty.write, message.data)
		elif message.type == MessageType.TERMINAL_RESIZE_REQUEST:
			self.set_size(message.rows, message.cols)
			message = TerminalResizeEvent(
				sender=self._sender,
				channel=self.back_channel,
				terminal_id=self.terminal_id,
				rows=self.rows,
				cols=self.cols,
			)
			await send_message(message)
		elif message.type == MessageType.TERMINAL_CLOSE_REQUEST:
			await self.close()
		else:
			logger.warning("Received invalid message type %r", message.type)

	async def close(self) -> None:
		if self._closing:
			return
		logger.info("Close terminal")
		self._closing = True
		try:
			if self._pty_reader_task:
				self._pty_reader_task.cancel()
			message = TerminalCloseEvent(sender=self._sender, channel=self.back_channel, terminal_id=self.terminal_id)
			await send_message(message)
			if self._pty:
				self._pty.close(True)
			if self.terminal_id in terminals:
				del terminals[self.terminal_id]

		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)


async def _process_message(message: Message) -> None:
	terminal = terminals.get(message.terminal_id)

	try:
		if isinstance(message, TerminalOpenRequest):
			if not terminal:
				terminal = Terminal(terminal_open_request=message, sender=get_messagebus_worker_id())
				terminals[message.terminal_id] = terminal
				msg = TerminalOpenEvent(
					sender=get_messagebus_worker_id(),
					channel=message.back_channel,
					terminal_id=message.terminal_id,
					back_channel=f"{get_messagebus_worker_id()}:terminal",
					rows=terminal.rows,
					cols=terminal.cols,
				)
				await send_message(msg)
			else:
				# Resize to redraw screen
				terminal.set_size(terminal.rows - 1, terminal.cols)
				terminal.set_size(terminal.rows, terminal.cols)
		elif terminal:
			await terminal.process_message(message)
		else:
			raise RuntimeError("Invalid terminal id")
	except Exception as err:  # pylint: disable=broad-except
		logger.warning(err, exc_info=True)
		if terminal:
			await terminal.close()
		else:
			msg = TerminalCloseEvent(sender=get_messagebus_worker_id(), channel=message.back_channel, terminal_id=message.terminal_id)
			await send_message(msg)


async def _messagebus_terminal_instance_worker() -> None:
	channel = f"{get_messagebus_worker_id()}:terminal"
	reader = MessageReader(channels={channel: "$"})
	async for _redis_id, message, _context in reader.get_messages():
		try:
			if message.type.startswith("file_"):
				await process_file_message(message)
			else:
				await _process_message(message)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)


async def _messagebus_terminal_request_worker() -> None:
	channel = "service:config:terminal"
	cgmr = ConsumerGroupMessageReader(
		consumer_group=channel,
		consumer_name=get_messagebus_worker_id(),
		channels={channel: "0"},
	)
	async for redis_id, message, _context in cgmr.get_messages():
		try:
			await _process_message(message)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
		# ACK Message
		await cgmr.ack_message(message.channel, redis_id)


async def messagebus_terminal_request_worker() -> None:
	try:
		await asyncio.gather(_messagebus_terminal_request_worker(), _messagebus_terminal_instance_worker())
	except StopAsyncIteration:
		pass
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
