# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application.teminal
"""

import asyncio
import pathlib
from typing import Optional

from fastapi import Query, UploadFile, status
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from websockets.exceptions import ConnectionClosedOK
from pexpect import spawn  # type: ignore[import]
from pexpect.exceptions import TIMEOUT, EOF  # type: ignore[import]
from OPSI.System import get_subprocess_environment  # type: ignore[import]

from .. import contextvar_client_session
from ..logging import logger
from ..config import config
from ..session import register_websocket
from . import app


PTY_READER_BLOCK_SIZE = 16 * 1024


def start_pty(shell="bash", lines=30, columns=120, cwd=None):
	sp_env = get_subprocess_environment()
	sp_env.update({"TERM": "xterm-256color"})
	return spawn(shell, dimensions=(lines, columns), env=sp_env, cwd=cwd)


async def pty_reader(websocket: WebSocket, pty: spawn):
	loop = asyncio.get_event_loop()
	while True:
		try:
			logger.trace("Read from pty")
			data: bytes = await loop.run_in_executor(None, pty.read_nonblocking, PTY_READER_BLOCK_SIZE, 0.01)
			logger.trace("=>>> %s", data)
			await websocket.send_bytes(data)
		except TIMEOUT:
			if websocket.client_state == WebSocketState.DISCONNECTED or app.is_shutting_down:
				break
		except EOF:
			# shell exit
			await websocket.close()
			break
		except (ConnectionClosedOK, WebSocketDisconnect) as err:
			logger.debug("pty_reader: %s", err)
			break


async def websocket_reader(websocket: WebSocket, pty: spawn):
	loop = asyncio.get_event_loop()
	while True:
		try:
			logger.trace("Read from websocket")
			data = await websocket.receive_text()
			logger.trace("<<<= %s", data)
			await loop.run_in_executor(None, pty.write, data)
		except (ConnectionClosedOK, WebSocketDisconnect) as err:
			logger.debug("websocket_reader: %s", err)
			break


@app.websocket("/admin/terminal/ws")
@register_websocket("Admin terminal websocket")
async def terminal_websocket_endpoint(
	websocket: WebSocket,
	terminal_id: str = Query(
		default=None,
		min_length=36,
		max_length=36,
		regex="^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
	),
	columns: Optional[int] = Query(default=120, embed=True),
	lines: Optional[int] = Query(default=30, embed=True),
):
	session = contextvar_client_session.get()
	if not session:
		logger.warning("Access to terminal websocket denied, invalid session")
		await websocket.close(code=4403)
		return

	if session.user_store.host or not session.user_store.isAdmin:
		logger.warning("Access to terminal websocket denied for user '%s'", session.user_store.username)
		await websocket.close(code=4403)
		return

	await websocket.accept()

	logger.info("Websocket client connected to terminal columns=%d, lines=%d", columns, lines)
	pty = start_pty(shell="bash", lines=lines, columns=columns, cwd="/var/lib/opsi")

	terminals = session.get("terminal_ws", {})
	terminals[terminal_id] = f"{config.node_name}:{pty.pid}"
	session.set("terminal_ws", terminals)
	await session.store(wait=True)
	terminals = session.get("terminal_ws")
	await asyncio.gather(websocket_reader(websocket, pty), pty_reader(websocket, pty))


@app.post("/admin/terminal/fileupload")
async def terminal_fileupload(terminal_id: str, file: UploadFile):
	session = contextvar_client_session.get()
	if not session:
		return JSONResponse("Invalid session", status_code=status.HTTP_403_FORBIDDEN)
	terminals = session.get("terminal_ws")
	if not terminals or terminal_id not in terminals:
		return JSONResponse("Invalid terminal id", status_code=status.HTTP_404_NOT_FOUND)

	node_name, tty_pid = terminals[terminal_id].split(":", 1)
	if node_name != config.node_name:
		return JSONResponse("Invalid node", status_code=status.HTTP_404_NOT_FOUND)

	cwd = pathlib.Path(f"/proc/{tty_pid}/cwd")
	if not cwd.exists():
		return JSONResponse("Invalid terminal id", status_code=status.HTTP_404_NOT_FOUND)

	filename = (cwd.readlink() / file.filename).absolute()
	orig_name = filename.name
	ext = 0
	while filename.exists():
		ext += 1
		filename = filename.with_name(f"{orig_name}.{ext}")

	filename.write_bytes(await file.read())  # type: ignore[arg-type]
	filename.chmod(0o660)
	return JSONResponse({"filename": str(filename.name)})
