# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebus.websocket
"""

import asyncio
import traceback
from typing import Union

from fastapi import APIRouter, FastAPI, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from msgpack import loads as msgpack_loads  # type: ignore[import]
from opsicommon.messagebus import (  # type: ignore[import]
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionOperation,
	ChannelSubscriptionRequestMessage,
	GeneralErrorMessage,
	Message,
	TerminalOpenRequest,
)
from opsicommon.utils import serialize  # type: ignore[import]
from starlette.concurrency import run_in_threadpool
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketState

from opsiconfd.worker import Worker

from ..application.utils import OpsiconfdWebSocketEndpoint
from ..config import config
from ..logging import get_logger
from ..utils import compress_data, decompress_data
from . import (
	get_messagebus_user_id_for_host,
	get_messagebus_user_id_for_service_worker,
	get_messagebus_user_id_for_user,
)
from .redis import MessageReader, send_message

messagebus_router = APIRouter()
logger = get_logger("opsiconfd.messagebus")


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
		worker = Worker()
		self._messagebus_worker_id = get_messagebus_user_id_for_service_worker(config.node_name, worker.worker_num)
		self._messagebus_user_id = ""
		self._user_channel = ""
		self._session_channel = ""
		self._compression: Union[str, None] = None
		self._messagebus_reader_task = Union[asyncio.Task, None]
		self._messagebus_reader = MessageReader()

	async def _send_message_to_websocket(self, websocket: WebSocket, message: Message) -> None:
		data = message.to_msgpack()
		if self._compression:
			data = await run_in_threadpool(compress_data, data, self._compression)

		if websocket.client_state != WebSocketState.CONNECTED:
			logger.warning("Websocket client not connected")
			return

		logger.debug("Message to websocket: %r", message)
		await websocket.send_bytes(data)

	async def messagebus_reader(self, websocket: WebSocket) -> None:
		self._messagebus_reader = MessageReader(
			channels={
				self._user_channel: ">",
				self._session_channel: ">",
			}
		)
		try:
			async for redis_id, message, _context in self._messagebus_reader.get_messages():
				await self._send_message_to_websocket(websocket, message)
				if message.channel == self._user_channel:
					# ACK message (set last-delivered-id)
					# asyncio.create_task(reader.ack_message(redis_id))
					await self._messagebus_reader.ack_message(message.channel, redis_id)
		except StopAsyncIteration:
			pass
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

	def _check_channel_access(self, channel: str) -> bool:
		if channel == "service:config:jsonrpc":
			return True
		if channel == "service:messagebus":
			return True
		if channel == self._session_channel:
			return True
		if channel == self._user_channel:
			return True
		if self.scope["session"].user_store.isAdmin:
			return True
		logger.warning("Access to channel %s denied for %s", channel, self.scope["session"].user_store.username, exc_info=True)
		return False

	async def _process_channel_subscription_message(self, websocket: WebSocket, message: Message) -> None:
		response = ChannelSubscriptionEventMessage(
			sender=self._messagebus_worker_id, channel=message.back_channel, subscribed_channels=[], error=None
		)
		for idx, channel in enumerate(message.channels):
			if channel == "@":
				message.channels[idx] = channel = self._user_channel
			elif channel == "$":
				message.channels[idx] = channel = self._session_channel
			if not self._check_channel_access(channel):
				response.error = {  # pylint: disable=loop-invariant-statement
					"code": 0,
					"message": f"Access to channel {channel!r} denied",
					"details": None,
				}
				break

		if not response.error:
			if message.operation == ChannelSubscriptionOperation.SET:
				await self._messagebus_reader.set_channels({ch: None for ch in message.channels})
			elif message.operation == ChannelSubscriptionOperation.ADD:
				await self._messagebus_reader.add_channels({ch: None for ch in message.channels})
			elif message.operation == ChannelSubscriptionOperation.REMOVE:
				await self._messagebus_reader.remove_channels(message.channels)
			else:
				response.error = {"code": 0, "message": f"Invalid operation {message.operation!r}", "details": None}

		if not response.error:
			response.subscribed_channels = await self._messagebus_reader.get_channel_names()

		await self._send_message_to_websocket(websocket, response)

	async def on_receive(self, websocket: WebSocket, data: bytes) -> None:
		message_id = None
		try:
			if self._compression:
				data = await run_in_threadpool(decompress_data, data, self._compression)
			msg_dict = msgpack_loads(data)
			if not isinstance(msg_dict, dict):
				raise ValueError("Invalid message received")

			message_id = msg_dict["id"]
			msg_dict["sender"] = self._messagebus_user_id

			message = Message.from_dict(msg_dict)
			if not message.back_channel or message.back_channel == "$":
				message.back_channel = self._session_channel
			elif message.back_channel == "@":
				message.back_channel = self._user_channel

			if not self._check_channel_access(message.channel) or not self._check_channel_access(message.back_channel):
				raise RuntimeError(f"Access to channel {message.channel!r} denied")

			logger.debug("Message from websocket: %r", message)

			if isinstance(message, ChannelSubscriptionRequestMessage):
				await self._process_channel_subscription_message(websocket, message)
			else:
				if isinstance(message, TerminalOpenRequest):
					if not message.terminal_id:
						raise ValueError("Terminal id is missing")
					await self._messagebus_reader.add_channels({f"terminal:{message.terminal_id}": "$"})
					channel_subscription_event = ChannelSubscriptionEventMessage(
						sender=self._messagebus_worker_id,
						channel=message.back_channel,
						subscribed_channels=await self._messagebus_reader.get_channel_names()
					)
					await self._send_message_to_websocket(websocket, channel_subscription_event)
				await send_message(message, serialize(vars(self.scope["session"].user_store)))
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err, exc_info=True)
			await self._send_message_to_websocket(
				websocket,
				GeneralErrorMessage(
					sender=self._messagebus_worker_id,
					channel=self._session_channel,
					ref_message_id=message_id,
					error={
						"code": 0,
						"message": str(err),
						"details": str(traceback.format_exc()) if self.scope["session"].user_store.isAdmin else None
					},
				)
			)

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

		self._user_channel = self._messagebus_user_id
		self._session_channel = f"session:{self.scope['session'].session_id}"

		self._messagebus_reader_task = asyncio.create_task(self.messagebus_reader(websocket))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		logger.info("Websocket client disconnected from messagebus")
		if isinstance(self._messagebus_reader_task, asyncio.Task):
			self._messagebus_reader_task.cancel()
