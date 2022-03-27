# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application.teminal
"""

import os
import pwd
import asyncio
import time
import pathlib
from typing import Dict, Optional, Any
import msgpack  # type: ignore[import]

import psutil
from fastapi import Query
from starlette.types import Scope, Receive, Send
from starlette.websockets import WebSocket, WebSocketDisconnect
from websockets.exceptions import ConnectionClosedOK
from pexpect import spawn  # type: ignore[import]
from pexpect.exceptions import TIMEOUT, EOF  # type: ignore[import]
from OPSI.System import get_subprocess_environment  # type: ignore[import]

from ..logging import logger
from ..config import config
from . import app
from .utils import OpsiconfdWebSocketEndpoint

PTY_READER_BLOCK_SIZE = 16 * 1024


def start_pty(shell, rows=30, cols=120, cwd=None):
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

	async def pty_reader(self, websocket: WebSocket):
		loop = asyncio.get_event_loop()
		while True:
			try:
				logger.trace("Read from pty")
				data: bytes = await loop.run_in_executor(None, self._pty.read_nonblocking, PTY_READER_BLOCK_SIZE, 0.01)
				# data: bytes = self._pty.read_nonblocking(PTY_READER_BLOCK_SIZE, 0.001)
				logger.trace(data)
				await websocket.send_bytes(
					await asyncio.get_event_loop().run_in_executor(None, msgpack.dumps, {"type": "terminal-read", "payload": data})
				)
			except TIMEOUT:
				pass
			except EOF:
				# shell exit
				await websocket.close()
				break
			except (ConnectionClosedOK, WebSocketDisconnect) as err:
				logger.debug("pty_reader: %s", err)
				break

	async def on_receive(self, websocket: WebSocket, data: Any) -> None:
		message = await asyncio.get_event_loop().run_in_executor(None, msgpack.loads, data)
		logger.trace(message)
		payload = message.get("payload")
		if message.get("type") == "terminal-write":
			# Do not wait for completion to minimize rtt
			asyncio.get_event_loop().run_in_executor(None, self._pty.write, payload)
		elif message.get("type") == "terminal-resize":
			asyncio.get_event_loop().run_in_executor(None, self._pty.setwinsize, payload.get("rows"), payload.get("cols"))
		elif message.get("type") == "file-transfer":
			response = await asyncio.get_event_loop().run_in_executor(None, self._handle_file_transfer, payload)
			if response:
				await websocket.send_bytes(
					await asyncio.get_event_loop().run_in_executor(
						None, msgpack.dumps, {"type": "file-transfer-result", "payload": response}
					)
				)
		else:
			logger.warning("Received invalid message type %r", message.get("type"))

	async def on_connect(  # pylint: disable=arguments-differ
		self,
		websocket: WebSocket,
		cols: Optional[int] = Query(default=120, embed=True),
		rows: Optional[int] = Query(default=30, embed=True),
	):

		if "terminal" in config.admin_interface_disabled_features:
			logger.warning("Access to terminal websocket denied, terminal disabled")
			await websocket.close(code=4403)

		logger.info("Websocket client connected to terminal cols=%d, rows=%d", cols, rows)

		cwd = pwd.getpwuid(os.getuid()).pw_dir
		self._pty = start_pty(shell=config.admin_interface_terminal_shell, rows=rows, cols=cols, cwd=cwd)

		self._pty_reader_task = asyncio.get_event_loop().create_task(self.pty_reader(websocket))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		logger.info("Terminal connection closed")
		if self._pty_reader_task:
			self._pty_reader_task.cancel()
		if self._pty:
			self._pty.close(True)

	def _handle_file_transfer(self, payload: Dict[str, Any]):
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
			for child in proc.children(recursive=True):
				try:
					dst_dir = child.cwd()
				except psutil.AccessDenied:
					# Child owned by an other user (su)
					return_absolute_path = True
					dst_dir = "/var/lib/opsi"
					if not os.path.exists(dst_dir):
						dst_dir = pwd.getpwuid(os.getuid()).pw_dir

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

		return None
