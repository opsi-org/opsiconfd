# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
websocket
"""

from __future__ import annotations

import asyncio
import multiprocessing
import time
from asyncio import sleep as asyncio_sleep
from asyncio.events import AbstractEventLoop
from typing import Any

from uvicorn.config import Config  # type: ignore[import]
from uvicorn.protocols.websockets.wsproto_impl import ConnectionState, WSProtocol
from uvicorn.server import ServerState
from wsproto import events

multiprocessing.allow_connection_pickling()
spawn = multiprocessing.get_context("spawn")


class WSProtocolPing(WSProtocol):
	def __init__(
		self, config: Config, server_state: ServerState, app_state: dict[str, Any], _loop: AbstractEventLoop | None = None
	) -> None:
		self._ping_interval = config.ws_ping_interval or 0.0
		self._ping_timeout = config.ws_ping_timeout or 0.0
		self._last_ping_sent = time.time()
		self._current_pong_timeout = 0.0
		super().__init__(config, server_state, app_state, _loop)

	async def _ping_pong_task(self) -> None:
		try:
			while True:
				wait_time = self._ping_interval
				if self.conn.state in (ConnectionState.LOCAL_CLOSING, ConnectionState.CLOSED):
					break
				if self.conn.state == ConnectionState.OPEN:
					now = time.time()
					if self._current_pong_timeout and now >= self._current_pong_timeout:
						self.logger.info("%s - WebSocket ping timeout", self.scope["client"])
						self.transport.abort()
						break
					if now >= self._last_ping_sent + self._ping_interval:
						self.logger.debug("%s - WebSocket send ping", self.scope["client"])
						self._last_ping_sent = now
						self._current_pong_timeout = now + self._ping_timeout
						self.transport.write(self.conn.send(events.Ping(payload=b"")))
						wait_time = self._ping_timeout + 1
				await asyncio_sleep(wait_time)
		except Exception as err:  # pylint: disable=broad-exception-caught
			self.logger.error(err)

	def handle_pong(self, event: events.Pong) -> None:  # pylint: disable=unused-argument
		self.logger.debug("%s - WebSocket reveived pong", self.scope["client"])
		self._current_pong_timeout = 0.0

	def handle_events(self) -> None:
		for event in self.conn.events():
			if isinstance(event, events.Request):
				self.handle_connect(event)
			elif isinstance(event, events.TextMessage):
				self.handle_text(event)
			elif isinstance(event, events.BytesMessage):
				self.handle_bytes(event)
			elif isinstance(event, events.CloseConnection):
				self.handle_close(event)
			elif isinstance(event, events.Ping):
				self.handle_ping(event)
			elif isinstance(event, events.Pong):
				self.handle_pong(event)

	def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
		super().connection_made(transport)
		if self._ping_interval > 0 and self._ping_timeout > 0:
			task = self.loop.create_task(self._ping_pong_task())
			task.add_done_callback(self.on_task_complete)
			self.tasks.add(task)
