# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application.teminal
"""

import asyncio
import os
import pathlib
import time
from asyncio import get_running_loop
from os import getuid
from pwd import getpwuid
from typing import Any, Dict, Optional

import psutil
from fastapi import Query
from msgpack import dumps as msgpack_dumps  # type: ignore[import]
from msgpack import loads as msgpack_loads  # type: ignore[import]
from OPSI.System import get_subprocess_environment  # type: ignore[import]
from opsicommon.messagebus import (  # type: ignore[import]
	Message,
	MessageType,
	TerminalCloseEvent,
	TerminalDataRead,
	TerminalOpenEvent,
	TerminalResizeEvent,
)
from pexpect import spawn  # type: ignore[import]
from pexpect.exceptions import EOF, TIMEOUT  # type: ignore[import]
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from websockets.exceptions import ConnectionClosedOK

from opsiconfd.messagebus import (
	get_messagebus_user_id_for_service_node,
	get_messagebus_user_id_for_service_worker,
)
from opsiconfd.messagebus.redis import (
	ConsumerGroupMessageReader,
	MessageReader,
	send_message,
)
from opsiconfd.worker import Worker

from ..config import config
from ..logging import logger
from . import app
from .utils import OpsiconfdWebSocketEndpoint

PTY_READER_BLOCK_SIZE = 16 * 1024


def start_pty(shell: str, rows: int | None = 30, cols: int | None = 120, cwd: str | None = None) -> spawn:
	rows = rows or 30
	cols = cols or 120
	sp_env = get_subprocess_environment()
	sp_env.update({"TERM": "xterm-256color"})
	return spawn(shell, dimensions=(rows, cols), env=sp_env, cwd=cwd)


@app.websocket_route("/admin/terminal/ws")
class TerminalWebsocket(OpsiconfdWebSocketEndpoint):
	encoding = "bytes"
	admin_only = True

	def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
		super().__init__(scope, receive, send)
		self._pty: spawn
		self._pty_reader_task: asyncio.Task
		self._file_transfers: Dict[str, Dict[str, Any]] = {}

	async def pty_reader(self, websocket: WebSocket) -> None:
		loop = get_running_loop()
		pty_reader_block_size = PTY_READER_BLOCK_SIZE
		try:
			while websocket.client_state == WebSocketState.CONNECTED:
				try:  # pylint: disable=loop-try-except-usage
					logger.trace("Read from pty")
					data: bytes = await loop.run_in_executor(None, self._pty.read_nonblocking, pty_reader_block_size, 0.01)
					# data: bytes = self._pty.read_nonblocking(pty_reader_block_size, 0.001)
					logger.trace(data)
					await websocket.send_bytes(
						await loop.run_in_executor(
							None, msgpack_dumps, {"type": "terminal-read", "payload": data}  # pylint: disable=loop-invariant-statement
						)  # pylint: disable=loop-invariant-statement
					)
				except TIMEOUT:  # pylint: disable=loop-invariant-statement
					pass
		except EOF:
			# shell exit
			await websocket.close()
		except (ConnectionClosedOK, WebSocketDisconnect) as err:
			logger.debug("pty_reader: %s", err)

	async def on_receive(self, websocket: WebSocket, data: Any) -> None:
		message = await get_running_loop().run_in_executor(None, msgpack_loads, data)
		logger.trace(message)
		payload = message.get("payload")
		if message.get("type") == "terminal-write":
			# Do not wait for completion to minimize rtt
			get_running_loop().run_in_executor(None, self._pty.write, payload)
		elif message.get("type") == "terminal-resize":
			get_running_loop().run_in_executor(None, self._pty.setwinsize, payload.get("rows"), payload.get("cols"))
		elif message.get("type") == "file-transfer":
			response = await get_running_loop().run_in_executor(None, self._handle_file_transfer, payload)
			if response:
				await websocket.send_bytes(
					await get_running_loop().run_in_executor(None, msgpack_dumps, {"type": "file-transfer-result", "payload": response})
				)
		else:
			logger.warning("Received invalid message type %r", message.get("type"))

	async def on_connect(  # pylint: disable=arguments-differ
		self,
		websocket: WebSocket,
		cols: Optional[int] = Query(default=120, embed=True),
		rows: Optional[int] = Query(default=30, embed=True),
	) -> None:

		if "terminal" in config.admin_interface_disabled_features:
			logger.warning("Access to terminal websocket denied, terminal disabled")
			await websocket.close(code=4403)

		logger.info("Websocket client connected to terminal cols=%d, rows=%d", cols, rows)

		cwd = getpwuid(getuid()).pw_dir
		self._pty = start_pty(shell=config.admin_interface_terminal_shell, rows=rows, cols=cols, cwd=cwd)

		self._pty_reader_task = get_running_loop().create_task(self.pty_reader(websocket))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		logger.info("Terminal connection closed")
		if self._pty_reader_task:
			self._pty_reader_task.cancel()
		if self._pty:
			self._pty.close(True)

	def _handle_file_transfer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
		if not payload.get("file_id"):
			return {"result": None, "error": "Payload incomplete"}

		if payload["file_id"] not in self._file_transfers:
			if not payload.get("name"):
				return {"file_id": payload["file_id"], "result": None, "error": "Payload incomplete"}

			try:
				proc = psutil.Process(int(self._pty.pid))
			except (psutil.NoSuchProcess, ValueError):
				return {"file_id": payload["file_id"], "result": None, "error": "Invalid process id"}

			dst_dir = proc.cwd()
			return_absolute_path = False
			psutil_access_denied = psutil.AccessDenied
			os_path_exists = os.path.exists
			for child in proc.children(recursive=True):
				try:  # pylint: disable=loop-try-except-usage
					dst_dir = child.cwd()
				except psutil_access_denied:
					# Child owned by an other user (su)
					return_absolute_path = True
					dst_dir = "/var/lib/opsi"
					if not os_path_exists(dst_dir):
						dst_dir = getpwuid(getuid()).pw_dir

			dst_path = pathlib.Path(dst_dir)
			try:
				dst_file: pathlib.Path = (dst_path / payload["name"]).absolute()
				orig_name = dst_file.name
				ext = 0
				while dst_file.exists():
					ext += 1
					dst_file = dst_file.with_name(f"{orig_name}.{ext}")

				dst_file.touch()
				dst_file.chmod(0o660)
				self._file_transfers[payload["file_id"]] = {
					"started": time.time(),
					"file": dst_file,
					"return_path": str(dst_file if return_absolute_path else dst_file.name),
				}

			except PermissionError:
				return {"file_id": payload["file_id"], "result": None, "error": "Permission denied"}

		if payload.get("data"):
			with open(self._file_transfers[payload["file_id"]]["file"], mode="ab") as file:
				file.write(payload["data"])

		if not payload.get("more_data"):
			result = {
				"file_id": payload["file_id"],
				"result": {"path": self._file_transfers[payload["file_id"]]["return_path"]},
				"error": None,
			}
			del self._file_transfers[payload["file_id"]]
			return result

		return {}


class Terminal:  # pylint: disable=too-many-instance-attributes
	default_rows = 30
	max_rows = 100
	default_cols = 120
	max_cols = 300

	def __init__(  # pylint: disable=too-many-arguments
		self, id: str, sender_id: str, receiver_id: str, rows: int = None, cols: int = None  # pylint: disable=invalid-name
	) -> None:
		self.id = id  # pylint: disable=invalid-name
		self.sender_id = sender_id
		self.receiver_id = receiver_id
		self.rows = self.default_rows
		self.cols = self.default_cols
		self._loop = get_running_loop()

		self.set_size(rows, cols)
		cwd = getpwuid(getuid()).pw_dir
		self._pty = start_pty(shell=config.admin_interface_terminal_shell, rows=self.rows, cols=self.cols, cwd=cwd)
		self._pty_reader_task = self._loop.create_task(self._pty_reader())
		self._closing = False

	def set_size(self, rows: int = None, cols: int = None) -> None:
		self.rows = min(max(1, int(rows or self.default_rows)), self.max_rows)
		self.cols = min(max(1, int(cols or self.default_cols)), self.max_cols)

	async def _pty_reader(self) -> None:
		pty_reader_block_size = PTY_READER_BLOCK_SIZE
		try:
			while self._pty and not self._closing:
				try:  # pylint: disable=loop-try-except-usage
					logger.trace("Read from pty")
					data = await self._loop.run_in_executor(  # pylint: disable=loop-invariant-statement
						None, self._pty.read_nonblocking, pty_reader_block_size, 0.01
					)
					logger.trace(data)
					message = TerminalDataRead(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
						sender=self.sender_id, channel=self.receiver_id, terminal_id=self.id, data=data
					)
					await send_message(message)
				except TIMEOUT:  # pylint: disable=loop-invariant-statement
					pass
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
			self.rows = message.rows
			self.cols = message.cols
			await self._loop.run_in_executor(None, self._pty.setwinsize, self.rows, self.cols)
			message = TerminalResizeEvent(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender=self.sender_id,
				channel=self.receiver_id,
				terminal_id=self.id,
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
			message = TerminalCloseEvent(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender=self.sender_id, channel=self.receiver_id, terminal_id=self.id
			)
			await send_message(message)
			if self._pty:
				self._pty.close(True)

		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)


terminals: Dict[str, "Terminal"] = {}


# TODO: test message values like terminal_id, expire terminal, cleanup terminals, set expire in messages, access control (terminal owner)
async def _process_message(message: Message) -> None:
	terminal = terminals.get(message.terminal_id)
	if terminal and terminal.receiver_id != message.sender:
		return
	if message.type == MessageType.TERMINAL_OPEN_REQUEST:
		if not terminal:
			worker = Worker()
			messagebus_worker_id = get_messagebus_user_id_for_service_worker(config.node_name, worker.worker_num)
			terminal = Terminal(
				id=message.terminal_id, sender_id=messagebus_worker_id, receiver_id=message.sender, rows=message.rows, cols=message.cols
			)
			terminals[terminal.id] = terminal
		msg = TerminalOpenEvent(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
			sender=messagebus_worker_id,
			channel=message.sender,
			terminal_id=terminal.id,
			terminal_channel=f"{messagebus_worker_id}:terminal",
			rows=terminal.rows,
			cols=terminal.cols,
		)
		await send_message(msg)
	else:
		if terminal:
			await terminal.process_message(message)
		else:
			msg = TerminalCloseEvent(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender=message.sender, channel=message.sender, terminal_id=message.terminal_id
			)
			await send_message(msg)


async def _messagebus_terminal_instance_worker() -> None:
	worker = Worker()
	messagebus_worker_id = get_messagebus_user_id_for_service_worker(config.node_name, worker.worker_num)
	channel = f"{messagebus_worker_id}:terminal"

	reader = MessageReader(channels={channel: "$"})
	async for _redis_id, message, _context in reader.get_messages():
		try:
			await _process_message(message)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)


async def _messagebus_terminal_request_worker() -> None:
	worker = Worker()
	messagebus_node_id = get_messagebus_user_id_for_service_node(config.node_name)
	messagebus_worker_id = get_messagebus_user_id_for_service_worker(config.node_name, worker.worker_num)
	channel = f"{messagebus_node_id}:terminal"
	consumer_group = f"{messagebus_node_id}:terminal"
	cgmr = ConsumerGroupMessageReader(channel=channel, consumer_group=consumer_group, consumer_name=messagebus_worker_id)
	async for redis_id, message, _context in cgmr.get_messages():
		try:
			await _process_message(message)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
		# ACK Message
		# asyncio.create_task(cgmr.ack_message(redis_id))
		await cgmr.ack_message(redis_id)


async def messagebus_terminal_request_worker() -> None:
	try:
		await asyncio.gather(_messagebus_terminal_request_worker(), _messagebus_terminal_instance_worker())
	except StopAsyncIteration:
		pass
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
