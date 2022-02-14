# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application.teminal
"""

import asyncio
from typing import Optional

from fastapi import Depends, Query
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from websockets.exceptions import ConnectionClosedOK
from pexpect import spawn  # type: ignore[import]
from pexpect.exceptions import TIMEOUT, EOF  # type: ignore[import]
from OPSI.System import get_subprocess_environment  # type: ignore[import]

from .. import contextvar_client_session
from ..logging import logger
from . import app


PTY_READER_BLOCK_SIZE = 16 * 1024


def start_pty(shell="bash", lines=30, columns=120, cwd=None):
	sp_env = get_subprocess_environment()
	sp_env.update({"TERM": "xterm-256color"})
	return spawn(shell, dimensions=(lines, columns), env=sp_env, cwd=cwd)


def terminal_websocket_parameters(
	columns: Optional[int] = Query(default=120, embed=True), lines: Optional[int] = Query(default=30, embed=True)
):
	return {"columns": columns, "lines": lines}


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


@app.websocket("/ws/terminal")
async def terminal_websocket_endpoint(websocket: WebSocket, params: dict = Depends(terminal_websocket_parameters)):
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

	columns = params["columns"]
	lines = params["lines"]

	logger.info("Websocket client connected to terminal columns=%d, lines=%d", columns, lines)
	pty = start_pty(shell="bash", lines=lines, columns=columns, cwd="/var/lib/opsi")

	await asyncio.gather(websocket_reader(websocket, pty), pty_reader(websocket, pty))
