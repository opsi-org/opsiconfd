# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
messagebus.websocket
"""

import re
import traceback
from asyncio import Task, create_task, sleep
from dataclasses import dataclass
from functools import lru_cache
from time import time
from typing import TYPE_CHECKING, Literal

import msgspec
from fastapi import APIRouter, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from opsicommon.messagebus import CONNECTION_SESSION_CHANNEL, CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionOperation,
	ChannelSubscriptionRequestMessage,
	Error,
	EventMessage,
	GeneralErrorMessage,
	Message,
	TraceRequestMessage,
	TraceResponseMessage,
	timestamp,
)
from starlette.concurrency import run_in_threadpool
from starlette.endpoints import WebSocketEndpoint
from starlette.status import (
	HTTP_401_UNAUTHORIZED,
	WS_1000_NORMAL_CLOSURE,
	WS_1011_INTERNAL_ERROR,
)
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from uvicorn.protocols.utils import ClientDisconnected
from wsproto.utilities import LocalProtocolError

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.logging import get_logger
from opsiconfd.utils import asyncio_create_task, compress_data, decompress_data
from opsiconfd.worker import Worker

if TYPE_CHECKING:
	from opsiconfd.backend.rpc.main import UnprotectedBackend


from . import (
	RESTRICTED_MESSAGE_TYPES,
	check_channel_name,
	get_config_service_channel,
	get_user_id_for_host,
	get_user_id_for_service_worker,
	get_user_id_for_user,
)
from .redis import (
	ConsumerGroupMessageReader,
	MessageReader,
	create_messagebus_session_channel,
	delete_channel,
	get_websocket_connected_users,
	send_message,
	update_websocket_count,
)

if TYPE_CHECKING:
	from opsiconfd.session import OPSISession

RE_USER_ID = re.compile("^[a-z-0-9_]$")


@dataclass
class MessagebusWebsocketStatistics:
	messages_sent: int = 0
	messages_received: int = 0


statistics = MessagebusWebsocketStatistics()
messagebus_router = APIRouter()
logger = get_logger("opsiconfd.messagebus")


def messagebus_setup(_app: FastAPI) -> None:
	_app.include_router(messagebus_router, prefix="/messagebus")


@messagebus_router.get("/")
async def messagebroker_index() -> HTMLResponse:
	return HTMLResponse("<h1>messagebus</h1>")


@messagebus_router.websocket_route("/v1")
class MessagebusWebsocket(WebSocketEndpoint):
	encoding = "bytes"
	_update_session_interval = 30.0

	def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
		super().__init__(scope, receive, send)
		self._worker = Worker.get_instance()
		self._messagebus_worker_id = get_user_id_for_service_worker(self._worker.id)
		self._messagebus_user_id = ""
		self._session_channel = ""
		self._compression: str | None = None
		self._messagebus_reader: list[MessageReader] = []
		self._manager_task: Task | None = None
		self._message_decoder = msgspec.msgpack.Decoder()
		self._backend: UnprotectedBackend = get_unprotected_backend()

	@property
	def _user_channel(self) -> str:
		return self._messagebus_user_id

	async def _check_authorization(self) -> None:
		if not self.scope.get("session"):
			raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Access to messagebus denied, no valid session found")
		if not self.scope["session"].authenticated:
			raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Access to messagebus denied, not authenticated")

	async def _send_message_to_websocket(self, websocket: WebSocket, message: Message) -> None:
		if isinstance(message, (TraceRequestMessage, TraceResponseMessage)):
			message.trace = message.trace or {}
			message.trace["broker_ws_send"] = timestamp()

		data = message.to_msgpack()
		if self._compression:
			data = await run_in_threadpool(compress_data, data, self._compression)

		if websocket.client_state != WebSocketState.CONNECTED or websocket.application_state != WebSocketState.CONNECTED:
			logger.debug("Websocket client not connected")
			return

		logger.debug("Message to websocket: %r", message)
		try:
			await websocket.send_bytes(data)
			statistics.messages_sent += 1
		except (ClientDisconnected, LocalProtocolError, WebSocketDisconnect) as err:
			# Websocket propably closed
			logger.debug("Failed to send message to websocket: %s", err)

	async def manager_task(self, websocket: WebSocket) -> None:
		try:
			session: OPSISession = self.scope["session"]
			update_session_time = 0.0
			while websocket.client_state == WebSocketState.CONNECTED and websocket.application_state == WebSocketState.CONNECTED:
				now = time()
				if now >= update_session_time + self._update_session_interval:
					if session.deleted:
						logger.info("Session %r deleted, closing websocket", session.session_id)
						await self._send_message_to_websocket(
							websocket,
							GeneralErrorMessage(
								sender=self._messagebus_worker_id,
								channel=self._session_channel,
								error=Error(code=None, message="Session deleted"),
							),
						)
						await websocket.close(code=WS_1000_NORMAL_CLOSURE)
						break
					else:
						update_session_time = now
						await self.scope["session"].update_messagebus_last_used()
				await sleep(1.0)
		except Exception as err:
			logger.error(err, exc_info=True)

	async def message_reader_task(self, websocket: WebSocket, reader: MessageReader) -> None:
		ack_all_messages = isinstance(reader, ConsumerGroupMessageReader)
		try:
			async for redis_id, message, _context in reader.get_messages():
				await self._send_message_to_websocket(websocket, message)
				if ack_all_messages or message.channel == self._user_channel:
					# ACK message (set last-delivered-id)
					# create_task(reader.ack_message(redis_id))
					await reader.ack_message(message.channel, redis_id)
		except StopAsyncIteration:
			pass
		except Exception as err:
			logger.error(err, exc_info=True)

	def _check_channel_access(self, channel: str, operation: Literal["read", "write"]) -> bool:
		if operation not in ("read", "write"):
			raise ValueError(f"Invalid channel operation {operation!r}")

		channel = check_channel_name(channel)

		if channel.startswith("session:"):
			return True
		if channel == self._user_channel:
			return True
		if channel.startswith("service:") and channel.endswith((":messagebus", ":jsonrpc")) and operation == "write":
			return True
		if self.scope["session"].is_admin:
			return True

		logger.warning("Access to channel %s denied for %s", channel, self.scope["session"].username, exc_info=True)
		return False

	@lru_cache
	def _check_message_type_access(self, message_type: str) -> bool:
		if message_type not in RESTRICTED_MESSAGE_TYPES:
			return True
		if RESTRICTED_MESSAGE_TYPES[message_type] in self._backend.available_modules:
			return True
		return False

	async def _get_subscribed_channels(self) -> dict[str, MessageReader]:
		channels = {}
		for reader in self._messagebus_reader:
			for channel in await reader.get_channel_names():
				channels[channel] = reader
		return channels

	async def _process_channel_subscription(
		self, websocket: WebSocket, channels: list[str], message: ChannelSubscriptionRequestMessage | None = None
	) -> None:
		subsciption_event = ChannelSubscriptionEventMessage(
			sender=self._messagebus_worker_id,
			channel=(message.back_channel if message else None) or self._session_channel,
			subscribed_channels=[],
			error=None,
		)
		operation = message.operation if message else ChannelSubscriptionOperation.ADD
		if operation not in (ChannelSubscriptionOperation.ADD, ChannelSubscriptionOperation.SET, ChannelSubscriptionOperation.REMOVE):
			err = f"Invalid operation {operation!r}"
			if not message:
				raise ValueError(err)
			subsciption_event.error = Error(code=0, message=err, details=None)
			await self._send_message_to_websocket(websocket, subsciption_event)
			return

		subscribed_channels: dict[str, MessageReader] = await self._get_subscribed_channels()

		for idx, channel in enumerate(channels):
			channel = channel.strip()
			if channel == CONNECTION_USER_CHANNEL:
				channel = self._user_channel
			elif channel == CONNECTION_SESSION_CHANNEL:
				channel = self._session_channel
			elif channel.startswith("service:config:"):
				# Rewrite service:config:... to service:depot:<configserver_id>:...
				channel = get_config_service_channel(channel)
			channels[idx] = channel

		remove_channels = []
		if operation == ChannelSubscriptionOperation.REMOVE:
			for channel in channels:
				# Removing session channel is not allowed
				if channel != self._session_channel and channel in subscribed_channels:
					remove_channels.append(channel)
		elif operation == ChannelSubscriptionOperation.SET:
			for channel in subscribed_channels:
				# Removing session channel is not allowed
				if channel != self._session_channel and channel not in channels:
					remove_channels.append(channel)

		remove_by_reader: dict[MessageReader, list[str]] = {}
		for channel in remove_channels:
			reader = subscribed_channels.get(channel)
			if reader:
				if reader not in remove_by_reader:
					remove_by_reader[reader] = []
				remove_by_reader[reader].append(channel)

		for reader, chans in remove_by_reader.items():
			if sorted(chans) == sorted(await reader.get_channel_names()):
				await reader.stop(wait=False)
				self._messagebus_reader.remove(reader)
			else:
				await reader.remove_channels(chans)

		if operation in (ChannelSubscriptionOperation.SET, ChannelSubscriptionOperation.ADD):
			message_reader_channels: dict[str, str] = {}
			for channel in channels:
				if not self._check_channel_access(channel, "read"):
					subsciption_event.error = Error(
						code=None,
						message=f"Write access to channel {channel!r} denied",
						details=None,
					)
					await self._send_message_to_websocket(websocket, subsciption_event)
					return

				if channel.startswith("service:"):
					consumer_name = f"{self._messagebus_user_id}:{self._session_channel.split(':', 1)[1]}"
					# ID "0" means: Start reading pending messages (not ACKed) and continue reading new messages
					reader = ConsumerGroupMessageReader(consumer_group=channel, consumer_name=consumer_name)
					await reader.set_channels({channel: "0"})
					self._messagebus_reader.append(reader)
					asyncio_create_task(self.message_reader_task(websocket, reader))
				else:
					# ID ">" means that we want to receive all undelivered messages.
					# ID "$" means that we only want new messages (added after reader was started).
					message_reader_channels[channel] = "$" if channel.startswith(("event:", "session:")) else ">"
					if channel.startswith("session:") and channel != self._session_channel:
						await create_messagebus_session_channel(
							owner_id=self._messagebus_user_id, session_id=channel.split(":", 2)[1], exists_ok=True
						)

			if message_reader_channels:
				msr = [
					# Check for exact class (ConsumerGroupMessageReader is subclass of MessageReader)
					r
					for r in self._messagebus_reader
					if type(r) == MessageReader
				]
				if msr:
					await msr[0].add_channels(message_reader_channels)  # type: ignore[arg-type]
				else:
					reader = MessageReader()
					await reader.set_channels(message_reader_channels)  # type: ignore[arg-type]
					self._messagebus_reader.append(reader)
					asyncio_create_task(self.message_reader_task(websocket, reader))

		subsciption_event.subscribed_channels = list(await self._get_subscribed_channels())
		await self._send_message_to_websocket(websocket, subsciption_event)

	async def _process_channel_subscription_message(self, websocket: WebSocket, message: ChannelSubscriptionRequestMessage) -> None:
		await self._process_channel_subscription(websocket=websocket, channels=message.channels, message=message)

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

		await self.scope["session"].update_messagebus_last_used()
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
		msg_dict = {}
		try:
			receive_timestamp = timestamp()
			if self._compression:
				data = await run_in_threadpool(decompress_data, data, self._compression)
			msg_dict = self._message_decoder.decode(data)
			if not isinstance(msg_dict, dict):
				raise ValueError("Invalid message received")

			message_id = msg_dict["id"]
			msg_dict["sender"] = self._messagebus_user_id
			message = Message.from_dict(msg_dict)

			if not message.back_channel or message.back_channel == CONNECTION_SESSION_CHANNEL:
				message.back_channel = self._session_channel
			elif message.back_channel == CONNECTION_USER_CHANNEL:
				message.back_channel = self._user_channel

			if message.channel == CONNECTION_SESSION_CHANNEL:
				message.channel = self._session_channel
			elif message.channel == CONNECTION_USER_CHANNEL:
				message.channel = self._user_channel
			elif message.channel.startswith("service:config:"):
				# Rewrite service:config:... to service:depot:<configserver_id>:...
				message.channel = get_config_service_channel(message.channel)

			if not self._check_channel_access(message.channel, "write") or not self._check_channel_access(message.back_channel, "write"):
				raise RuntimeError(f"Read access to channel {message.channel!r} denied")
			if not self._check_message_type_access(message.type):
				raise RuntimeError(f"Access to message type {message.type!r} denied - check license")
			logger.debug("Message from websocket: %r", message)
			statistics.messages_received += 1

			if isinstance(message, ChannelSubscriptionRequestMessage):
				await self._process_channel_subscription_message(websocket, message)
			else:
				if isinstance(message, (TraceRequestMessage, TraceResponseMessage)):
					message.trace = message.trace or {}
					message.trace["broker_ws_receive"] = receive_timestamp

				await send_message(message, self.scope["session"].serialize())

		except Exception as err:
			logger.warning("%s (msg_dict=%s)", err, msg_dict, exc_info=True)
			await self._send_message_to_websocket(
				websocket,
				GeneralErrorMessage(
					sender=self._messagebus_worker_id,
					channel=self._session_channel,
					ref_id=message_id,
					error=Error(
						code=None,
						message=str(err),
						details=str(traceback.format_exc()) if self.scope["session"].is_admin else None,
					),
				),
			)

	async def on_connect(self, websocket: WebSocket) -> None:
		logger.info("Websocket client connected to messagebus")
		session: OPSISession = self.scope["session"]

		event = EventMessage(
			sender=self._messagebus_worker_id,
			channel="",
			event="",
			data={
				"client_address": session.client_addr,
				"worker": self._worker.id,
			},
		)

		if session.host:
			self._messagebus_user_id = get_user_id_for_host(session.host.id)

			user_type: Literal["client", "depot"] = "client" if session.host.getType() == "OpsiClient" else "depot"
			connected = bool([u async for u in get_websocket_connected_users(user_ids=[session.host.id], user_type=user_type)])
			if not connected:
				event.event = "host_connected"
				event.channel = "event:host_connected"
				event.data["host"] = {
					"type": session.host.getType(),
					"id": session.host.id,
				}
		elif session.username and session.is_admin:
			self._messagebus_user_id = get_user_id_for_user(session.username)

			connected = bool([u async for u in get_websocket_connected_users(user_ids=[session.username], user_type="user")])
			if not connected:
				event.event = "user_connected"
				event.channel = "event:user_connected"
				event.data["user"] = {"id": session.username, "username": session.username}
		else:
			raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid session")

		await update_websocket_count(session, 1)

		self._session_channel = await create_messagebus_session_channel(owner_id=self._messagebus_user_id, exists_ok=True)
		await self._process_channel_subscription(websocket=websocket, channels=[self._user_channel, self._session_channel])

		await send_message(event)

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		logger.info("Websocket client disconnected from messagebus")
		for reader in self._messagebus_reader:
			try:
				await reader.stop(wait=False)
			except Exception as err:
				logger.error(err, exc_info=True)

		session: OPSISession = self.scope["session"]

		await update_websocket_count(session, -1)
		await delete_channel(self._session_channel)

		event = EventMessage(
			sender=self._messagebus_worker_id,
			channel="",
			event="",
			data={
				"client_address": session.client_addr,
				"worker": self._worker.id,
			},
		)

		if session.host:
			user_type: Literal["client", "depot"] = "client" if session.host.getType() == "OpsiClient" else "depot"
			connected = bool([u async for u in get_websocket_connected_users(user_ids=[session.host.id], user_type=user_type)])
			if not connected:
				event.event = "host_disconnected"
				event.channel = "event:host_disconnected"
				event.data["host"] = {
					"type": session.host.getType(),
					"id": session.host.id,
				}
				await send_message(event)
		elif session.username:
			connected = bool([u async for u in get_websocket_connected_users(user_ids=[session.username], user_type="user")])
			if not connected:
				event.event = "user_disconnected"
				event.channel = "event:user_disconnected"
				event.data["user"] = {"id": session.username, "username": session.username}
				await send_message(event)

		# Wait for task to finish to prevent that task is ended by garbage collector
		for reader in self._messagebus_reader:
			await reader.wait_stopped()
