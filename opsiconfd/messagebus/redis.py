# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.redis
"""

from __future__ import annotations

from asyncio import Event, Lock, sleep
from asyncio.exceptions import CancelledError
from contextlib import asynccontextmanager
from time import time
from typing import TYPE_CHECKING, Any, AsyncGenerator, Literal
from uuid import UUID, uuid4

import msgspec
from opsicommon.messagebus import (  # type: ignore[import]
	Message,
	TraceRequestMessage,
	TraceResponseMessage,
	timestamp,
)
from redis.asyncio import StrictRedis
from redis.exceptions import ResponseError, WatchError
from redis.typing import StreamIdT

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.config import config
from opsiconfd.logging import get_logger
from opsiconfd.redis import async_delete_recursively, async_redis_client, redis_client

from . import get_user_id_for_host

if TYPE_CHECKING:
	from opsiconfd.session import OPSISession


logger = get_logger("opsiconfd.messagebus")


CHANNEL_INFO_SUFFIX = b":info"


async def messagebus_cleanup(full: bool = False) -> None:
	logger.debug("Messagebus cleanup")
	if full:
		await async_delete_recursively(f"{config.redis_key('messagebus')}:connections")
	await cleanup_channels(full)


async def cleanup_channels(full: bool = False) -> None:
	logger.debug("Cleaning up messagebus channels")
	backend = get_unprotected_backend()
	depot_ids = []
	client_ids = []
	host_channels = []
	for host in backend.host_getObjects(attributes=["id"]):
		if host.getType() in ("OpsiConfigserver", "OpsiDepotserver"):
			depot_ids.append(host.id)
		else:
			client_ids.append(host.id)
		host_channels.append(get_user_id_for_host(host.id))

	redis = await async_redis_client()

	channel_prefix = f"{config.redis_key('messagebus')}:channels:"
	channel_prefix_len = len(channel_prefix)

	if full:
		for obj in ("service_worker", "service_node"):
			logger.debug("Deleting user channels for %r", obj)
			await async_delete_recursively(f"{channel_prefix}{obj}")
		await async_delete_recursively(f"{channel_prefix}session")

	# async for key_b in redis.scan_iter(f"{channel_prefix}service:*"):
	# 	key = key_b.decode("utf-8")
	# 	stream = await redis.xinfo_stream(name=key, full=True)
	# 	for group in stream["groups"]:
	# 		for consumer in group["consumers"]:
	# 			print(consumer)

	remove_keys = []
	async for key_b in redis.scan_iter(f"{channel_prefix}host:*"):
		key = key_b.decode("utf-8")
		host_channel = ":".join(key[channel_prefix_len:].split(":", 2)[:2])
		if host_channel not in host_channels:
			logger.debug("Removing key %s (host not found)", key)
			remove_keys.append(key)

	if remove_keys:
		pipeline = redis.pipeline()
		for key in remove_keys:
			pipeline.delete(key)
		await pipeline.execute()


_context_encoder = msgspec.msgpack.Encoder()


def _prepare_send_message(message: Message, context: Any = None) -> bytes | None:
	if isinstance(message, (TraceRequestMessage, TraceResponseMessage)):
		message.trace = message.trace or {}
		message.trace["broker_redis_send"] = timestamp()
	context_data = None
	if context:
		context_data = _context_encoder.encode(context)
	return context_data


async def send_message(message: Message, context: Any = None) -> None:
	context_data = _prepare_send_message(message, context)
	logger.debug("Message to redis: %r", message)
	await send_message_msgpack(message.channel, message.to_msgpack(), context_data)


def sync_send_message(message: Message, context: Any = None) -> None:
	context_data = _prepare_send_message(message, context)
	logger.debug("Message to redis: %r", message)
	sync_send_message_msgpack(message.channel, message.to_msgpack(), context_data)


async def send_message_msgpack(channel: str, msgpack_data: bytes, context_data: bytes | None = None) -> None:
	redis = await async_redis_client()
	fields = {"message": msgpack_data}
	if context_data:
		fields["context"] = context_data
	await redis.xadd(f"{config.redis_key('messagebus')}:channels:{channel}", fields=fields)  # type: ignore[arg-type]


def sync_send_message_msgpack(channel: str, msgpack_data: bytes, context_data: bytes | None = None) -> None:
	with redis_client() as redis:
		fields = {"message": msgpack_data}
		if context_data:
			fields["context"] = context_data
		redis.xadd(f"{config.redis_key('messagebus')}:channels:{channel}", fields=fields)  # type: ignore[arg-type]


async def create_messagebus_session_channel(owner_id: str, session_id: str | None = None, exists_ok: bool = True) -> str:
	redis = await async_redis_client()
	session_id = str(UUID(session_id) if session_id else uuid4())
	channel = f"session:{session_id}"
	stream_key = f"{config.redis_key('messagebus')}:channels:{channel}".encode("utf-8")
	exists = await redis.exists(stream_key)
	if exists:
		if not exists_ok:
			raise RuntimeError("Already exists")
	else:
		pipeline = redis.pipeline()
		pipeline.hset(stream_key + CHANNEL_INFO_SUFFIX, "owner-id", owner_id)
		pipeline.hset(stream_key + CHANNEL_INFO_SUFFIX, "reader-count", 0)
		await pipeline.execute()
	return channel


async def delete_channel(channel: str) -> None:
	redis = await async_redis_client()
	stream_key = f"{config.redis_key('messagebus')}:channels:{channel}".encode("utf-8")
	await redis.unlink(stream_key)


@asynccontextmanager
async def session_channel(owner_id: str, session_id: str | None = None, exists_ok: bool = True) -> AsyncGenerator[str, None]:
	channel = await create_messagebus_session_channel(owner_id=owner_id, session_id=session_id, exists_ok=exists_ok)
	try:
		yield channel
	finally:
		await delete_channel(channel)


async def update_websocket_count(session: OPSISession, increment: int) -> None:
	redis = await async_redis_client()

	state_key = None
	host = session.host
	if host:
		if host.getType() == "OpsiClient":
			state_key = f"{config.redis_key('messagebus')}:connections:clients:{host.id}"
		elif host.getType() == "OpsiDepotserver":
			state_key = f"{config.redis_key('messagebus')}:connections:depots:{host.id}"
	else:
		state_key = f"{config.redis_key('messagebus')}:connections:users:{session.username}"

	if not state_key:
		return

	try:
		async with redis.pipeline(transaction=True) as pipe:
			attempt = 0
			while True:
				attempt += 1
				try:
					await pipe.watch(state_key)
					val = await pipe.hget(state_key, "websocket_count")
					val = max(0, int(val or 0)) + increment
					pipe.multi()
					pipe.hset(state_key, "websocket_count", val)
					await pipe.execute()
					break
				except WatchError:
					pass
				except Exception as err:  # pylint: disable=broad-except
					logger.error("Failed to update messagebus websocket count: %s", err, exc_info=True)
					break
				if attempt >= 10:
					logger.error("Failed to update messagebus websocket count")
				await sleep(0.1)
	except CancelledError:
		pass


async def get_websocket_connected_users(
	user_ids: list[str] | None = None, user_type: Literal["client", "depot", "user"] | None = None
) -> AsyncGenerator[str, None]:
	redis = await async_redis_client()

	state_keys = []
	if user_type and user_ids:
		state_keys = [f"{config.redis_key('messagebus')}:connections:{user_type}s:{i}" for i in user_ids]
	else:
		search_base = f"{config.redis_key('messagebus')}:connections"
		if user_type:
			search_base = f"{search_base}:{user_type}s"
		state_keys = [k.decode("utf-8") async for k in redis.scan_iter(f"{search_base}:*")]

	for state_key in state_keys:
		try:
			user_id = state_key.rsplit(":", 1)[-1]
			if user_ids and user_id not in user_ids:
				continue
			if int(await redis.hget(state_key, "websocket_count") or 0) > 0:
				yield user_id
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to read messagebus websocket count: %s", err, exc_info=True)


class MessageReader:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
	_info_suffix = CHANNEL_INFO_SUFFIX
	_count_readers = True

	def __init__(self, channels: dict[str, StreamIdT | None] | None = None, default_stream_id: str = "$") -> None:
		"""
		channels:
			A dict of channel names to stream IDs, where
			IDs indicate the last ID already seen.
			Special IDs:
			ID ">" means that we want to receive all undelivered messages.
			ID "$" means that we only want new messages (added after reader was started).
		"""
		self._channels = channels or {}
		self._default_stream_id = default_stream_id
		self._streams: dict[bytes, StreamIdT] = {}
		self._key_prefix = f"{config.redis_key('messagebus')}:channels"
		self._should_stop = False
		self._stopped_event = Event()
		self._context_decoder = msgspec.msgpack.Decoder()
		self._channels_lock = Lock()

	def __repr__(self) -> str:
		return f"{self.__class__.__name__}({','.join(self._channels)})"

	__str__ = __repr__

	async def _update_streams(self) -> None:
		redis = await async_redis_client()
		stream_keys: list[bytes] = []
		redis_time = await redis.time()
		redis_time_id = str(int(redis_time[0] * 1000 + redis_time[1] / 1000))
		for channel, redis_msg_id in self._channels.items():
			stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
			redis_msg_id = redis_msg_id or self._streams.get(stream_key) or self._default_stream_id
			if redis_msg_id == ">":
				last_delivered_id = await redis.hget(stream_key + self._info_suffix, "last-delivered-id")
				logger.debug("Last delivered id of channel %r: %r", channel, last_delivered_id)
				if last_delivered_id:
					redis_msg_id = last_delivered_id.decode("utf-8")
				else:
					redis_msg_id = "0"

			if redis_msg_id == "$":
				# Reading will start slightly later
				# Use current timestamp instead of $ to do not miss messages
				redis_msg_id = redis_time_id

			if not redis_msg_id:
				raise ValueError("No redis message id")

			if self._count_readers and stream_key not in self._streams:
				await redis.hincrby(stream_key + self._info_suffix, "reader-count", 1)

			self._streams[stream_key] = redis_msg_id
			stream_keys.append(stream_key)

		for stream_key in list(self._streams):
			if self._count_readers and stream_key not in stream_keys:
				await redis.hincrby(stream_key + self._info_suffix, "reader-count", -1)
				del self._streams[stream_key]
		logger.debug("%s updated streams: %s", self, self._streams)

	async def get_channel_names(self) -> list[str]:
		async with self._channels_lock:
			return list(self._channels)

	async def set_channels(self, channels: dict[str, StreamIdT | None]) -> None:
		async with self._channels_lock:
			self._channels = channels
			await self._update_streams()

	async def add_channels(self, channels: dict[str, StreamIdT | None]) -> None:
		async with self._channels_lock:
			self._channels.update(channels)
			await self._update_streams()

	async def remove_channels(self, channels: list[str]) -> None:
		async with self._channels_lock:
			for channel in channels:
				if channel in self._channels:
					del self._channels[channel]
			await self._update_streams()

	async def _get_stream_entries(self, redis: StrictRedis) -> dict:
		return await redis.xread(streams=self._streams, block=1000, count=10)  # type: ignore[arg-type]

	async def get_messages(  # pylint: disable=too-many-branches,too-many-locals
		self, timeout: float = 0.0
	) -> AsyncGenerator[tuple[str, Message, Any], None]:
		if not self._channels:
			raise ValueError("No channels to read from")

		_logger = logger
		async with self._channels_lock:
			try:
				await self._update_streams()
			except Exception as err:
				logger.error(err, exc_info=True)
				raise

		_logger.debug("%s: getting messages", self)

		redis = await async_redis_client()
		start = time()
		end = start + timeout if timeout else 0.0
		try:  # pylint: disable=too-many-nested-blocks
			while not self._should_stop:
				try:
					now = time()
					stream_entries = await self._get_stream_entries(redis)
					if not stream_entries:
						if end >= now:
							return
						continue
					for stream_key, messages in stream_entries:
						last_redis_msg_id = ">"
						for message in messages:
							redis_msg_id = message[0].decode("utf-8")
							context = None
							context_data = message[1].get(b"context")
							if context_data:
								context = self._context_decoder.decode(context_data)
							msg = Message.from_msgpack(message[1][b"message"])
							_logger.debug("Message from redis: %r", msg)
							if msg.expires and msg.expires <= now:
								continue
							if isinstance(msg, (TraceRequestMessage, TraceResponseMessage)):
								msg.trace = msg.trace or {}
								msg.trace["broker_redis_receive"] = timestamp()
							yield redis_msg_id, msg, context
							last_redis_msg_id = redis_msg_id
						self._streams[stream_key] = last_redis_msg_id
				except Exception as err:  # pylint: disable=broad-except
					_logger.error(err, exc_info=True)
					await sleep(3)
		except CancelledError:
			pass
		try:
			if self._count_readers:
				# Do not run in a pipeline, can result in problems on application shutdown
				for stream_key in list(self._streams):
					await redis.hincrby(stream_key + self._info_suffix, "reader-count", -1)
		finally:
			self._stopped_event.set()

	async def ack_message(self, channel: str, redis_msg_id: str) -> None:
		logger.trace("ACK channel %r, message %r", channel, redis_msg_id)
		redis = await async_redis_client()
		stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
		if stream_key not in self._streams:
			raise ValueError(f"Invalid channel: {channel!r}")
		await redis.hset(stream_key + self._info_suffix, "last-delivered-id", redis_msg_id)

	async def stop(self, wait: bool = True) -> None:
		self._should_stop = True
		if wait:
			await self._stopped_event.wait()


class ConsumerGroupMessageReader(MessageReader):
	_count_readers = False

	def __init__(
		self, consumer_group: str, consumer_name: str, channels: dict[str, StreamIdT | None] | None = None, default_stream_id: str = "0"
	) -> None:
		"""
		ID ">" means that the consumer want to receive only messages that were never delivered to any other consumer.
		Any other ID, that is, 0 or any other valid ID will have the effect of returning entries that are pending
		for the consumer sending the command with IDs greater than the one provided.
		So basically if the ID is not ">", then the command will just let the client access its pending entries:
		messages delivered to it, but not yet acknowledged.
		"""
		super().__init__(channels, default_stream_id)
		self._consumer_group = consumer_group.encode("utf-8")
		self._consumer_name = consumer_name.encode("utf-8")

	@property
	def consumer_name(self) -> str:
		return self._consumer_name.decode("utf-8")

	@property
	def consumer_group(self) -> str:
		return self._consumer_group.decode("utf-8")

	async def _update_streams(self) -> None:
		redis = await async_redis_client()
		stream_keys: list[bytes] = []
		for channel, redis_msg_id in self._channels.items():
			stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
			try:
				await redis.xgroup_create(stream_key, self._consumer_group, id="0", mkstream=True)
			except ResponseError as err:
				if str(err).startswith("BUSYGROUP"):
					# Consumer Group name already exists
					pass
				else:
					raise

			start_id = redis_msg_id or "0"
			self._streams[stream_key] = start_id
			stream_keys.append(stream_key)
			try:
				# Autoclaim idle (60 seconds) pending messages (XAUTOCLAIM is available since Redis 6.2)
				await redis.xautoclaim(stream_key, self._consumer_group, self._consumer_name, min_idle_time=60_000, start_id=start_id)
			except ResponseError as err:
				if "unknown command" in str(err):
					# Redis before 6.2
					pass
				else:
					raise

		for stream_key in list(self._streams):
			if stream_key not in stream_keys:
				del self._streams[stream_key]

	async def _get_stream_entries(self, redis: StrictRedis) -> dict:
		return await redis.xreadgroup(
			self._consumer_group, self._consumer_name, streams=self._streams, block=1000, count=10  # type: ignore[arg-type]
		)

	async def ack_message(self, channel: str, redis_msg_id: str) -> None:
		redis = await async_redis_client()
		stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
		if stream_key not in self._streams:
			raise ValueError(f"Invalid channel: {channel!r}")
		await redis.xack(stream_key, self._consumer_group, redis_msg_id)  # type: ignore[no-untyped-call]
