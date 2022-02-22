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
import pathlib
from typing import Optional, Any

import psutil
from fastapi import Query, UploadFile, status
from fastapi.responses import JSONResponse
from starlette.types import Scope, Receive, Send
from starlette.websockets import WebSocket, WebSocketDisconnect
from websockets.exceptions import ConnectionClosedOK
from pexpect import spawn  # type: ignore[import]
from pexpect.exceptions import TIMEOUT, EOF  # type: ignore[import]
from OPSI.System import get_subprocess_environment  # type: ignore[import]

from .. import contextvar_client_session
from ..logging import logger
from ..config import config
from . import app
from .utils import OpsiconfdWebSocketEndpoint

PTY_READER_BLOCK_SIZE = 16 * 1024


def start_pty(shell, lines=30, columns=120, cwd=None):
	sp_env = get_subprocess_environment()
	sp_env.update({"TERM": "xterm-256color"})
	return spawn(shell, dimensions=(lines, columns), env=sp_env, cwd=cwd)


@app.websocket_route("/admin/terminal/ws")
class TerminalWebsocket(OpsiconfdWebSocketEndpoint):
	encoding = "text"
	admin_only = True

	def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
		super().__init__(scope, receive, send)
		self._pty: spawn
		self._pty_reader_task: asyncio.Task

	async def pty_reader(self, websocket: WebSocket):
		loop = asyncio.get_event_loop()
		while True:
			try:
				logger.trace("Read from pty")
				data: bytes = await loop.run_in_executor(None, self._pty.read_nonblocking, PTY_READER_BLOCK_SIZE, 0.01)
				# data: bytes = self._pty.read_nonblocking(PTY_READER_BLOCK_SIZE, 0.001)
				logger.trace("=>>> %s", data)
				await websocket.send_bytes(data)
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
		# logger.trace(data.encode("ascii").hex())
		# Do not wait for completion to minimize rtt
		asyncio.get_event_loop().run_in_executor(None, self._pty.write, data)

	async def on_connect(  # pylint: disable=arguments-differ
		self,
		websocket: WebSocket,
		terminal_id: str = Query(
			default=None,
			regex="^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
		),
		columns: Optional[int] = Query(default=120, embed=True),
		lines: Optional[int] = Query(default=30, embed=True),
	):

		if "terminal" in config.admin_interface_disabled_features:
			logger.warning("Access to terminal websocket denied, terminal disabled")
			await websocket.close(code=4403)

		logger.info("Websocket client connected to terminal columns=%d, lines=%d", columns, lines)

		cwd = pwd.getpwuid(os.getuid()).pw_dir
		self._pty = start_pty(shell=config.admin_interface_terminal_shell, lines=lines, columns=columns, cwd=cwd)

		session = self.scope["session"]
		terminals = session.get("terminal_ws", {})
		terminals[terminal_id] = f"{config.node_name}:{self._pty.pid}"
		session.set("terminal_ws", terminals)
		await session.store(wait=True)
		terminals = session.get("terminal_ws")

		self._pty_reader_task = asyncio.get_event_loop().create_task(self.pty_reader(websocket))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		if self._pty_reader_task:
			self._pty_reader_task.cancel()


@app.post("/admin/terminal/fileupload")
async def terminal_fileupload(terminal_id: str, file: UploadFile):  # pylint: disable=too-many-return-statements
	if "terminal" in config.admin_interface_disabled_features:
		return JSONResponse("Terminal disabled", status_code=status.HTTP_404_NOT_FOUND)

	session = contextvar_client_session.get()
	if not session:
		return JSONResponse("Invalid session", status_code=status.HTTP_403_FORBIDDEN)
	terminals = session.get("terminal_ws")
	if not terminals or terminal_id not in terminals:
		return JSONResponse("Invalid terminal id", status_code=status.HTTP_403_FORBIDDEN)

	node_name, tty_pid = terminals[terminal_id].split(":", 1)
	if node_name != config.node_name:
		return JSONResponse("Invalid node", status_code=status.HTTP_403_FORBIDDEN)

	try:
		proc = psutil.Process(int(tty_pid))
	except (psutil.NoSuchProcess, ValueError):
		return JSONResponse("Invalid process id", status_code=status.HTTP_403_FORBIDDEN)

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
		dst_file = (dst_path / file.filename).absolute()
		orig_name = dst_file.name
		ext = 0
		while dst_file.exists():
			ext += 1
			dst_file = dst_file.with_name(f"{orig_name}.{ext}")

		dst_file.write_bytes(await file.read())  # type: ignore[arg-type]
		dst_file.chmod(0o660)
		return JSONResponse({"filename": str(dst_file if return_absolute_path else dst_file.name)})
	except PermissionError as err:
		return JSONResponse(str(err), status_code=status.HTTP_403_FORBIDDEN)
