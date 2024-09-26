# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.messagebus.redis
"""

from __future__ import annotations

from asyncio import Event, Lock, Task, create_task, sleep
from asyncio.exceptions import CancelledError
from contextlib import asynccontextmanager
from logging import DEBUG
from typing import TYPE_CHECKING, Any, AsyncGenerator, Literal
from uuid import UUID, uuid4

import msgspec
from opsicommon.logging.constants import TRACE
from opsicommon.messagebus.message import (
	Message,
	TraceRequestMessage,
	TraceResponseMessage,
	timestamp,
)
from redis.exceptions import ResponseError
from redis.typing import StreamIdT

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.config import config
from opsiconfd.logging import get_logger
from opsiconfd.messagebus import check_channel_name
from opsiconfd.redis import async_delete_recursively, async_redis_client, redis_client, redis_supports_xtrim_minid

from . import get_user_id_for_host

if TYPE_CHECKING:
	from redis.asyncio import StrictRedis

	from opsiconfd.session import OPSISession

logger = get_logger("opsiconfd.messagebus")


CHANNEL_INFO_SUFFIX = b":info"
MAX_STREAM_LENGTH = 1000
MAX_STREAM_LENGTH_EVENT = 50
MAX_STREAM_LENGTH_HOST = 100
STREAM_RECORD_MAX_AGE_SECONDS = 300


async def messagebus_cleanup(full: bool = False) -> None:
	logger.debug("Messagebus cleanup")
	if full:
		await async_delete_recursively(f"{config.redis_key('messagebus')}:connections")
	await cleanup_channels(full)


async def cleanup_channels(full: bool = False, trim_approximate: bool = True) -> None:
	logger.debug("Cleaning up messagebus channels")
	backend = get_unprotected_backend()
	redis = await async_redis_client()

	channel_prefix = f"{config.redis_key('messagebus')}:channels:"
	channel_prefix_len = len(channel_prefix)

	if full:
		for obj in ("service_worker", "service_node"):
			logger.debug("Deleting user channels for %r", obj)
			await async_delete_recursively(f"{channel_prefix}{obj}")
		await async_delete_recursively(f"{channel_prefix}session")

	# async for key_b in redis.scan_iter(f"{channel_prefix}service:*", count=1000):
	# 	key = key_b.decode("utf-8")
	# 	stream = await redis.xinfo_stream(name=key, full=True)
	# 	for group in stream["groups"]:
	# 		for consumer in group["consumers"]:
	# 			print(consumer)

	depot_ids = []
	client_ids = []
	host_channels = []
	for host in backend.host_getObjects(attributes=["id"]):
		if host.getType() in ("OpsiConfigserver", "OpsiDepotserver"):
			depot_ids.append(host.id)
		else:
			client_ids.append(host.id)
		host_channels.append(get_user_id_for_host(host.id))

	channel_info_suffix = CHANNEL_INFO_SUFFIX.decode("utf-8")
	stream_keys = set()
	channel_info_keys = set()
	remove_keys = set()
	async for key_b in redis.scan_iter(f"{channel_prefix}*", count=1000):
		key = str(key_b.decode("utf-8"))
		if key.endswith(channel_info_suffix):
			channel_info_keys.add(key)
			continue

		stream_keys.add(key)
		channel = key[channel_prefix_len:]
		try:
			check_channel_name(channel)
		except ValueError as err:
			logger.debug("Removing key %r (%s)", key, err)
			remove_keys.add(key)
			continue

		if channel.startswith("host:"):
			host_channel = ":".join(channel.split(":", 2)[:2])
			if host_channel not in host_channels:
				logger.debug("Removing key %r (host not found)", key)
				remove_keys.add(key)

	stream_keys -= remove_keys
	# Remove info keys for non-existing streams
	remove_keys.update(k for k in channel_info_keys if k.removesuffix(channel_info_suffix) not in stream_keys)
	minid = int(timestamp() - STREAM_RECORD_MAX_AGE_SECONDS * 1000) if redis_supports_xtrim_minid() else None
	if remove_keys or stream_keys:
		pipeline = redis.pipeline()
		for key in remove_keys:
			pipeline.unlink(key)
		for stream_key in stream_keys:
			# trim_approximate should always be true for performance reasons
			# trim_approximate = false is used for testing only
			if minid is not None:
				pipeline.xtrim(stream_key, minid=minid, approximate=trim_approximate)
			else:
				maxlen = MAX_STREAM_LENGTH
				if stream_key.startswith(f"{channel_prefix}host:"):
					maxlen = MAX_STREAM_LENGTH_HOST
				elif stream_key.startswith(f"{channel_prefix}event:"):
					maxlen = MAX_STREAM_LENGTH_EVENT
				pipeline.xtrim(stream_key, maxlen=maxlen, approximate=trim_approximate)
		await pipeline.execute()

	if full:
		now_ts = timestamp()  # Current unix timestamp in milliseconds
		for obj in ("host", "user"):
			key = f"{channel_prefix}{obj}"
			remove_keys = set()
			all_info_keys = set()
			async for key_b in redis.scan_iter(f"{channel_prefix}{obj}:*", count=1000):
				if key_b.endswith(CHANNEL_INFO_SUFFIX):
					continue

				logger.trace("Checking %r", key_b)
				info_key_b = key_b + CHANNEL_INFO_SUFFIX

				info = await redis.hgetall(info_key_b)
				if info:
					all_info_keys.add(info_key_b)
					last_delivered_id = info.get(b"last-delivered-id")
					if last_delivered_id:
						try:
							ts = int(last_delivered_id.decode("utf-8").split("-", 1)[0])
						except Exception as err:
							logger.debug("Failed to read channel info: %s", err, exc_info=True)
							ts = 0
						if (now_ts - ts) > 7776000000:  # 90 days
							remove_keys.add(key_b)
							remove_keys.add(info_key_b)
				else:
					remove_keys.add(key_b)

			keep_info_keys = all_info_keys - remove_keys
			pipeline = redis.pipeline()
			for key in remove_keys:
				logger.debug("Removing %r", key)
				pipeline.unlink(key)
			for key in keep_info_keys:
				logger.debug("Resetting reader-count on %r", key)
				pipeline.hset(key, "reader-count", 0)
			await pipeline.execute()


_context_encoder = msgspec.msgpack.Encoder()


def _prepare_send_message(message: Message, context: Any = None) -> dict[str, bytes]:
	if isinstance(message, (TraceRequestMessage, TraceResponseMessage)):
		message.trace = message.trace or {}
		message.trace["broker_redis_send"] = timestamp()
	fields = {"message": message.to_msgpack()}
	if context:
		fields["context"] = _context_encoder.encode(context)
	return fields


async def send_message(message: Message, context: Any = None) -> None:
	fields = _prepare_send_message(message, context)
	logger.debug("Message to redis: %r", message)
	if not message.channel:
		raise ValueError("Channel not set")

	redis = await async_redis_client()
	await redis.xadd(
		f"{config.redis_key('messagebus')}:channels:{message.channel}",
		maxlen=MAX_STREAM_LENGTH,
		approximate=True,
		fields=fields,  # type: ignore[arg-type]
	)


def sync_send_message(message: Message, context: Any = None) -> None:
	fields = _prepare_send_message(message, context)
	logger.debug("Message to redis: %r", message)
	if not message.channel:
		raise ValueError("Channel not set")

	redis_client().xadd(
		f"{config.redis_key('messagebus')}:channels:{message.channel}",
		maxlen=MAX_STREAM_LENGTH,
		approximate=True,
		fields=fields,  # type: ignore[arg-type]
	)


async def create_messagebus_session_channel(*, owner_id: str, purpose: str, session_id: str | None = None, exists_ok: bool = True) -> str:
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
		# Add one message to create the stream, the message will be ignored by the reader
		pipeline.xadd(stream_key, fields={"ignore": ""})
		pipeline.hset(stream_key + CHANNEL_INFO_SUFFIX, mapping={"owner-id": owner_id, "purpose": purpose, "reader-count": 0})
		await pipeline.execute()
	return channel


async def delete_channel(channel: str) -> None:
	redis = await async_redis_client()
	stream_key = f"{config.redis_key('messagebus')}:channels:{channel}".encode("utf-8")
	stream_key_info = stream_key + CHANNEL_INFO_SUFFIX
	await redis.unlink(stream_key_info, stream_key)


@asynccontextmanager
async def session_channel(
	*, owner_id: str, purpose: str, session_id: str | None = None, exists_ok: bool = True
) -> AsyncGenerator[str, None]:
	channel = await create_messagebus_session_channel(owner_id=owner_id, purpose=purpose, session_id=session_id, exists_ok=exists_ok)
	try:
		yield channel
	finally:
		await delete_channel(channel)


async def update_websocket_count(session: OPSISession, increment: int) -> None:
	redis = await async_redis_client()

	state_key = None
	if session.host_id:
		if session.host_type == "OpsiClient":
			state_key = f"{config.redis_key('messagebus')}:connections:clients:{session.host_id}"
		elif session.host_type == "OpsiDepotserver":
			state_key = f"{config.redis_key('messagebus')}:connections:depots:{session.host_id}"
	else:
		state_key = f"{config.redis_key('messagebus')}:connections:users:{session.username}"

	if not state_key:
		return

	try:
		await redis.hincrby(state_key, "websocket_count", increment)
	except Exception as err:
		logger.error("Failed to update messagebus websocket count: %s", err, exc_info=True)


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
		state_keys = [k.decode("utf-8") async for k in redis.scan_iter(f"{search_base}:*", count=1000)]

	for state_key in state_keys:
		try:
			user_id = state_key.rsplit(":", 1)[-1]
			if user_ids and user_id not in user_ids:
				continue
			if int(await redis.hget(state_key, "websocket_count") or 0) > 0:
				yield user_id
		except Exception as err:
			logger.error("Failed to read messagebus websocket count: %s", err, exc_info=True)


class MessageReader:
	"""
	Redis Messagebus reader.

	If multiple readers are reading the same channel,
	all readers will receive the same messages.

	It is possible to ACK messages.
	Messages which are ACKed will not be delivered again
	if a new reader is starting to read the channel.

	channels:
	        A dict of channel names to stream IDs,
	        where IDs indicate the last ID already seen.
	        Special IDs:
	        ID ">" means that we want to receive all undelivered messages.
	        ID "$" means that we only want new messages (added after reader was started).
	"""

	_info_suffix = CHANNEL_INFO_SUFFIX
	_count_readers = True
	_xread_block_time = 3600_000
	_xread_count = 25

	def __init__(self, name: str | None = None) -> None:
		self.name: str = name or str(id(self))
		self._channels: dict[str, StreamIdT] = {}
		self._streams: dict[bytes, StreamIdT] = {}
		self._key_prefix = f"{config.redis_key('messagebus')}:channels"
		self._should_stop = False
		self._stopped_event = Event()
		self._context_decoder = msgspec.msgpack.Decoder()
		self._channels_lock = Lock()
		self._get_stream_entries_task: Task | None = None

	def __repr__(self) -> str:
		return f"{self.__class__.__name__}({self.name})"

	__str__ = __repr__

	async def _update_streams(self) -> None:
		redis = await async_redis_client()
		stream_keys: list[bytes] = []
		redis_time = await redis.time()
		redis_time_id = str(int(redis_time[0] * 1000 + redis_time[1] / 1000))
		for channel, redis_msg_id in self._channels.items():
			stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
			stream_keys.append(stream_key)
			if stream_key in self._streams:
				# Already in streams
				continue

			# redis_msg_id = self._streams.get(stream_key, redis_msg_id)
			if not redis_msg_id:
				raise ValueError(f"Missing redis message id for channel {channel:!r}")

			if redis_msg_id == ">":
				# ID ">" means that we want to receive all undelivered messages.
				# Receive all undelivered messages
				# Use last-delivered-id if available or "0" which means all messages inside the stream.
				last_delivered_id = await redis.hget(stream_key + self._info_suffix, "last-delivered-id")
				logger.debug("Last delivered id of channel %r: %r", channel, last_delivered_id)
				if last_delivered_id:
					redis_msg_id = last_delivered_id.decode("utf-8")
				else:
					redis_msg_id = "0"

			elif redis_msg_id == "$":
				# ID "$" means that we only want new messages (added after reader was started).
				# For redis streams "$" means the ID of the item with the greatest ID inside the stream.
				# Not using "$" because stream reading will start slightly later.
				# Using the current timestamp instead to do not miss messages.
				redis_msg_id = redis_time_id

			if self._count_readers:
				await redis.hincrby(stream_key + self._info_suffix, "reader-count", 1)

			self._streams[stream_key] = redis_msg_id

		for stream_key in list(self._streams):
			if self._count_readers and stream_key not in stream_keys:
				await redis.hincrby(stream_key + self._info_suffix, "reader-count", -1)
				del self._streams[stream_key]

		# Streams have changed, cancel the current read task, so that the new streams are read
		self._cancel_get_stream_entries()
		logger.debug("%s updated streams: %s", self, self._streams)

	async def get_channel_names(self) -> list[str]:
		async with self._channels_lock:
			return list(self._channels)

	async def set_channels(self, channels: dict[str, StreamIdT]) -> None:
		async with self._channels_lock:
			self._channels = channels
			await self._update_streams()

	async def add_channels(self, channels: dict[str, StreamIdT]) -> None:
		async with self._channels_lock:
			self._channels.update(channels)
			await self._update_streams()

	async def remove_channels(self, channels: list[str]) -> None:
		async with self._channels_lock:
			for channel in channels:
				if channel in self._channels:
					del self._channels[channel]
			await self._update_streams()

	def _cancel_get_stream_entries(self) -> None:
		if self._get_stream_entries_task:
			logger.debug("Cancelling get_stream_entries")
			self._get_stream_entries_task.cancel()

	async def _get_stream_entries(self, redis: StrictRedis) -> dict:
		if logger.isEnabledFor(DEBUG):
			logger.debug("MessageReader %r is reading %d streams", self.name, len(self._streams))
			if logger.isEnabledFor(TRACE):
				logger.trace("Streams: %s", list(self._streams))

		self._get_stream_entries_task = create_task(
			redis.xread(
				streams=self._streams,
				block=self._xread_block_time,
				count=self._xread_count,
			)
		)
		try:
			await self._get_stream_entries_task
			return self._get_stream_entries_task.result()
		except CancelledError:
			logger.debug("MessageReader was cancelled")
		return {}

	async def get_messages(self, timeout: float = 0.0) -> AsyncGenerator[tuple[str, Message, Any], None]:
		if not self._channels:
			raise ValueError("No channels to read from")

		_logger = logger

		try:
			_logger.debug("%s: getting messages", self)

			redis = await async_redis_client()
			start_ts = timestamp()
			end_ts = 0
			if timeout:
				end_ts = start_ts + round(timeout * 1000)

			while not self._should_stop:
				try:
					if not self._streams:
						await sleep(0.1)
					stream_entries = await self._get_stream_entries(redis)
					now_ts = timestamp()  # Current unix timestamp in milliseconds
					if not stream_entries:
						if self._should_stop:
							break
						if end_ts and now_ts > end_ts:
							_logger.debug("Reader timed out after %0.2f seconds", (now_ts - end_ts) / 1000)
							break
						continue

					for stream_key, messages in stream_entries:
						next_redis_msg_id = ""
						for message in messages:
							next_redis_msg_id = redis_msg_id = message[0].decode("utf-8")
							context = None
							context_data = message[1].get(b"context")
							if context_data:
								context = self._context_decoder.decode(context_data)
							message_data = message[1].get(b"message")
							if not message_data:
								if not message[1].get(b"ignore"):
									logger.warning("Received malformed message from redis: %r", message)
								continue
							msg = Message.from_msgpack(message_data)
							_logger.debug("Message from redis: %r", msg)
							if msg.expires and msg.expires <= now_ts:
								_logger.debug("Message is expired (%r <= %r)", msg.expires, now_ts)
								continue
							if isinstance(msg, (TraceRequestMessage, TraceResponseMessage)):
								msg.trace = msg.trace or {}
								msg.trace["broker_redis_receive"] = timestamp()
							yield redis_msg_id, msg, context

						# Update the ID in self._streams[stream_key] which will be
						# used in _get_stream_entries for xread / xreadgroup.
						# This ID is volatile and valid only for the current reader.
						# A persistent tracking can be done with consumer groups / ACK.
						if next_redis_msg_id:
							self._streams[stream_key] = next_redis_msg_id
						elif isinstance(self, ConsumerGroupMessageReader):
							# next_redis_msg_id not set, which means that no messages where received.
							# If the ID was set to a numeric ID initially, this also means that all
							# pending messages have been read.
							# In this case the ID must be set to ">" to start reading new messages.
							self._streams[stream_key] = ">"
				except Exception as err:
					_logger.error(err, exc_info=True)
					await sleep(3)
		except CancelledError:
			pass
		finally:
			try:
				if self._count_readers:
					# Do not run in a pipeline, can result in problems on application shutdown
					for stream_key in list(self._streams):
						info_key = stream_key + self._info_suffix
						# Test if the info key still exists (do not recerate it)
						if await redis.exists(info_key):
							await redis.hincrby(info_key, "reader-count", -1)
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
		self._cancel_get_stream_entries()

		if wait:
			await self.wait_stopped()

	async def wait_stopped(self) -> None:
		await self._stopped_event.wait()


class ConsumerGroupMessageReader(MessageReader):
	"""
	Redis Messagebus Consumer group reader.

	If multiple readers of the same consumer group are reading the same channel,
	each message is delivered to a different consumer.

	All messages must be ACKed.
	ACKed messages will not be delivered again.

	channels:
	        A dict of channel names to stream IDs

	        ID ">" means that we want to receive messages never delivered to other consumers so far.
	        Messages that have already been delivered but not ACKed will not be delivered again!

	        If the ID is any valid numerical ID, all pending messages (starting from the specified ID) will be delivered first.
	        Pending messages means messages that are intended for the specified consumer but were never acknowledged.
	        After delivering the pending messages, the reader will act as if ID ">" was passed.
	        This is different from the normal XACK behavior of redis.
	"""

	_count_readers = False

	def __init__(self, consumer_group: str, consumer_name: str) -> None:
		"""
		consumer_group:
		        Name of a consumer group
		consumer_name:
		        Name of the consumer as member of the consumer group
		"""
		super().__init__(name=f"{consumer_group}/{consumer_name}")
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
		if logger.isEnabledFor(DEBUG):
			logger.debug("ConsumerGroupMessageReader %r is reading %d streams", self.name, len(self._streams))
			if logger.isEnabledFor(TRACE):
				logger.trace("Streams: %s", list(self._streams))

		self._get_stream_entries_task = create_task(
			redis.xreadgroup(
				self._consumer_group,
				self._consumer_name,
				streams=self._streams,
				block=self._xread_block_time,
				count=self._xread_count,
			)
		)
		try:
			await self._get_stream_entries_task
			return self._get_stream_entries_task.result()
		except CancelledError:
			logger.debug("ConsumerGroupMessageReader was cancelled")
		return {}

	async def ack_message(self, channel: str, redis_msg_id: str) -> None:
		redis = await async_redis_client()
		stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
		if stream_key not in self._streams:
			raise ValueError(f"Invalid channel: {channel!r}")
		await redis.xack(stream_key, self._consumer_group, redis_msg_id)  # type: ignore[no-untyped-call]
