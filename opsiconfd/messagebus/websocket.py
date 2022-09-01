# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebus.websocket
"""

import asyncio
from typing import Union

from fastapi import APIRouter, FastAPI, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from msgpack import loads as msgpack_loads  # type: ignore[import]
from opsicommon.messagebus import Message  # type: ignore[import]
from opsicommon.utils import serialize  # type: ignore[import]
from starlette.concurrency import run_in_threadpool
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketState

from ..application.utils import OpsiconfdWebSocketEndpoint
from ..logging import logger
from ..utils import compress_data, decompress_data
from . import get_messagebus_user_id_for_host, get_messagebus_user_id_for_user
from .redis import ConsumerGroupMessageReader, send_message

messagebus_router = APIRouter()


def messagebus_setup(_app: FastAPI) -> None:
	_app.include_router(messagebus_router, prefix="/messagebus")


@messagebus_router.get("/")
async def messagebroker_index() -> HTMLResponse:
	return HTMLResponse("<h1>messagebus</h1>")


@messagebus_router.websocket_route("/v1")
class MessagebusWebsocket(OpsiconfdWebSocketEndpoint):
	encoding = "bytes"
	admin_only = False

	def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
		super().__init__(scope, receive, send)
		self._messagebus_user_id = ""
		self._compression: Union[str, None] = None
		self._messagebus_reader_task = Union[asyncio.Task, None]

	async def messagebus_reader(self, websocket: WebSocket) -> None:
		cgmr = ConsumerGroupMessageReader(
			channel=self._messagebus_user_id, consumer_group=self._messagebus_user_id, consumer_name=self._messagebus_user_id
		)
		try:
			async for redis_id, message, _context in cgmr.get_messages():
				data = message.to_msgpack()
				if self._compression:
					data = await run_in_threadpool(compress_data, data, self._compression)

				if websocket.client_state != WebSocketState.CONNECTED:
					logger.warning("Websocket client not connected")
					return

				await websocket.send_bytes(data)
				# ACK message
				# asyncio.create_task(cgmr.ack_message(redis_id))
				await cgmr.ack_message(redis_id)
		except StopAsyncIteration:
			pass

	def _check_channel_access(self, channel: str) -> None:
		if channel == "service:config:jsonrpc":
			return
		if not self.scope["session"].user_store.isAdmin:
			raise RuntimeError(f"Access to channel {channel!r} denied")

	async def on_receive(self, websocket: WebSocket, data: bytes) -> None:
		try:
			if self._compression:
				data = await run_in_threadpool(decompress_data, data, self._compression)
			msg_dict = msgpack_loads(data)
			msg_dict["sender"] = self._messagebus_user_id
			self._check_channel_access(msg_dict["channel"])
			message = Message.from_dict(msg_dict)
			await send_message(message, serialize(self.scope["session"].user_store.__dict__))
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err)
			await websocket.close(code=status.WS_1003_UNSUPPORTED_DATA, reason=str(err))

	async def on_connect(  # pylint: disable=arguments-differ
		self, websocket: WebSocket, compression: Union[str, None] = Query(default=None, embed=True)
	) -> None:
		logger.info("Websocket client connected to messagebus")
		if compression:
			if compression not in ("lz4", "gzip"):
				msg = f"Invalid compression {compression!r}, valid compressions are lz4 and gzip"
				logger.error(msg)
				raise HTTPException(
					status_code=status.HTTP_400_BAD_REQUEST,
					detail=msg,
				)
			self._compression = compression

		if self.scope["session"].user_store.host:
			self._messagebus_user_id = get_messagebus_user_id_for_host(self.scope["session"].user_store.host.id)
		elif self.scope["session"].user_store.isAdmin:
			self._messagebus_user_id = get_messagebus_user_id_for_user(self.scope["session"].user_store.username)
		self._messagebus_reader_task = asyncio.get_running_loop().create_task(self.messagebus_reader(websocket))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		logger.info("Websocket client disconnected from messagebus")
		if isinstance(self._messagebus_reader_task, asyncio.Task):
			self._messagebus_reader_task.cancel()
