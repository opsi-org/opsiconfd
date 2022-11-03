# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebus.websocket
"""

import traceback
from asyncio import Task, create_task, sleep
from time import time
from typing import Union

from fastapi import APIRouter, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from msgpack import loads as msgpack_loads  # type: ignore[import]
from opsicommon.messagebus import (  # type: ignore[import]
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionOperation,
	ChannelSubscriptionRequestMessage,
	GeneralErrorMessage,
	Message,
	TraceRequestMessage,
	TraceResponseMessage,
	timestamp,
)
from opsicommon.utils import serialize  # type: ignore[import]
from starlette.concurrency import run_in_threadpool
from starlette.endpoints import WebSocketEndpoint
from starlette.status import (
	HTTP_401_UNAUTHORIZED,
	WS_1000_NORMAL_CLOSURE,
	WS_1011_INTERNAL_ERROR,
)
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketState

from opsiconfd.worker import Worker

from ..config import config
from ..logging import get_logger
from ..utils import compress_data, decompress_data
from . import (
	get_messagebus_user_id_for_host,
	get_messagebus_user_id_for_service_worker,
	get_messagebus_user_id_for_user,
)
from .redis import MessageReader, create_messagebus_session_channel, send_message

messagebus_router = APIRouter()
logger = get_logger("opsiconfd.messagebus")


def messagebus_setup(_app: FastAPI) -> None:
	_app.include_router(messagebus_router, prefix="/messagebus")


@messagebus_router.get("/")
async def messagebroker_index() -> HTMLResponse:
	return HTMLResponse("<h1>messagebus</h1>")


@messagebus_router.websocket_route("/v1")
class MessagebusWebsocket(WebSocketEndpoint):  # pylint: disable=too-many-instance-attributes
	encoding = "bytes"

	def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
		super().__init__(scope, receive, send)
		worker = Worker.get_instance()
		self._messagebus_worker_id = get_messagebus_user_id_for_service_worker(config.node_name, worker.worker_num)
		self._messagebus_user_id = ""
		self._user_channel = ""
		self._session_channel = ""
		self._compression: Union[str, None] = None
		self._messagebus_reader_task = Union[Task, None]
		self._messagebus_reader = MessageReader()
		self._manager_task = Union[Task, None]

	async def _check_authorization(self) -> None:
		if not self.scope.get("session"):
			raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Access to messagebus denied, no valid session found")
		if not self.scope["session"].user_store or not self.scope["session"].user_store.authenticated:
			raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Access to messagebus denied, not authenticated")

	async def _send_message_to_websocket(self, websocket: WebSocket, message: Message) -> None:
		if isinstance(message, (TraceRequestMessage, TraceResponseMessage)):
			message.trace["broker_ws_send"] = timestamp()

		data = message.to_msgpack()
		if self._compression:
			data = await run_in_threadpool(compress_data, data, self._compression)

		if websocket.client_state != WebSocketState.CONNECTED:
			logger.warning("Websocket client not connected")
			return

		logger.debug("Message to websocket: %r", message)
		await websocket.send_bytes(data)

	async def manager_task(self, websocket: WebSocket) -> None:
		update_session_interval = 5.0
		update_session_time = time()
		while websocket.client_state == WebSocketState.CONNECTED:
			await sleep(1.0)
			now = time()
			if update_session_time + update_session_interval <= now:
				update_session_time = now
				await self.scope["session"].update_last_used()  # pylint: disable=loop-invariant-statement

	async def messagebus_reader(self, websocket: WebSocket) -> None:
		self._messagebus_reader = MessageReader()
		await self._messagebus_reader.add_channels(
			channels={
				self._user_channel: ">",
				self._session_channel: ">",
			}
		)
		await self._send_message_to_websocket(
			websocket,
			ChannelSubscriptionEventMessage(
				sender=self._messagebus_worker_id,
				channel=self._session_channel,
				subscribed_channels=[self._user_channel, self._session_channel],
			),
		)
		try:
			async for redis_id, message, _context in self._messagebus_reader.get_messages():
				await self._send_message_to_websocket(websocket, message)
				if message.channel == self._user_channel:
					# ACK message (set last-delivered-id)
					# create_task(reader.ack_message(redis_id))
					await self._messagebus_reader.ack_message(message.channel, redis_id)
		except StopAsyncIteration:
			pass
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

	def _check_channel_access(self, channel: str) -> bool:  # pylint: disable=too-many-return-statements
		if channel.startswith("session:"):
			return True
		if channel == "service:config:jsonrpc":
			return True
		if channel == "service:messagebus":
			return True
		# if channel == self._session_channel:
		# 	return True
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

			if channel.startswith("session:"):
				await create_messagebus_session_channel(
					owner_id=self._messagebus_user_id, session_id=channel.split(":", 2)[1], exists_ok=True
				)

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

	async def dispatch(self) -> None:
		websocket = WebSocket(self.scope, receive=self.receive, send=self.send)
		await self._check_authorization()

		compression = websocket.query_params.get("compression")
		if compression:
			if compression not in ("lz4", "gzip"):
				msg = f"Invalid compression {compression!r}, valid compressions are lz4 and gzip"
				logger.error(msg)
				raise HTTPException(
					status_code=status.HTTP_400_BAD_REQUEST,
					detail=msg,
				)
			self._compression = compression

		await websocket.accept()

		self._manager_task = create_task(self.manager_task(websocket))

		await self.on_connect(websocket)

		close_code = WS_1000_NORMAL_CLOSURE
		try:
			while True:
				message = await websocket.receive()
				if message["type"] == "websocket.receive":
					data = await self.decode(websocket, message)
					await self.on_receive(websocket, data)
				elif message["type"] == "websocket.disconnect":
					close_code = int(message.get("code", WS_1000_NORMAL_CLOSURE))
					break
		except Exception as exc:
			close_code = WS_1011_INTERNAL_ERROR
			raise exc
		finally:
			await self.on_disconnect(websocket, close_code)

	async def on_receive(self, websocket: WebSocket, data: bytes) -> None:
		message_id = None
		try:
			receive_timestamp = timestamp()
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

			if message.channel == "$":
				message.channel = self._session_channel
			elif message.channel == "@":
				message.channel = self._user_channel

			if not self._check_channel_access(message.channel) or not self._check_channel_access(message.back_channel):
				raise RuntimeError(f"Access to channel {message.channel!r} denied")

			logger.debug("Message from websocket: %r", message)

			if isinstance(message, ChannelSubscriptionRequestMessage):
				await self._process_channel_subscription_message(websocket, message)
			else:
				if isinstance(message, (TraceRequestMessage, TraceResponseMessage)):
					message.trace["broker_ws_receive"] = receive_timestamp

				# if isinstance(message, TerminalOpenRequest):
				# 	if not message.terminal_id:
				# 		raise ValueError("Terminal id is missing")
				# 	await self._messagebus_reader.add_channels({f"terminal:{message.terminal_id}": "$"})
				# 	channel_subscription_event = ChannelSubscriptionEventMessage(
				# 		sender=self._messagebus_worker_id,
				# 		channel=message.back_channel,
				# 		subscribed_channels=await self._messagebus_reader.get_channel_names()
				# 	)
				# 	await self._send_message_to_websocket(websocket, channel_subscription_event)
				await send_message(message, serialize(vars(self.scope["session"].user_store)))
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err, exc_info=True)
			await self._send_message_to_websocket(
				websocket,
				GeneralErrorMessage(
					sender=self._messagebus_worker_id,
					channel=self._session_channel,
					ref_id=message_id,
					error={
						"code": 0,
						"message": str(err),
						"details": str(traceback.format_exc()) if self.scope["session"].user_store.isAdmin else None,
					},
				),
			)

	async def on_connect(self, websocket: WebSocket) -> None:  # pylint: disable=arguments-differ
		logger.info("Websocket client connected to messagebus")

		if self.scope["session"].user_store.host:
			self._messagebus_user_id = get_messagebus_user_id_for_host(self.scope["session"].user_store.host.id)
		elif self.scope["session"].user_store.isAdmin:
			self._messagebus_user_id = get_messagebus_user_id_for_user(self.scope["session"].user_store.username)

		self._user_channel = self._messagebus_user_id
		self._session_channel = await create_messagebus_session_channel(owner_id=self._messagebus_user_id, exists_ok=False)

		self._messagebus_reader_task = create_task(self.messagebus_reader(websocket))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:  # pylint: disable=unused-argument
		logger.info("Websocket client disconnected from messagebus")
		if self._messagebus_reader:
			self._messagebus_reader.stop()
