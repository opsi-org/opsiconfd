# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.redis
"""

from asyncio import sleep
from asyncio.exceptions import CancelledError
from time import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from aioredis import StrictRedis
from aioredis.client import StreamIdT
from aioredis.exceptions import ResponseError
from msgpack import dumps, loads  # type: ignore[import]
from opsicommon.messagebus import Message  # type: ignore[import]

from ..config import REDIS_PREFIX_MESSAGEBUS
from ..logging import get_logger
from ..utils import async_redis_client

logger = get_logger("opsiconfd.messagebus")


async def send_message_msgpack(channel: str, msgpack_data: bytes, context_data: bytes = None) -> None:
	redis = await async_redis_client()
	fields = {"message": msgpack_data}
	if context_data:
		fields["context"] = context_data
	await redis.xadd(f"{REDIS_PREFIX_MESSAGEBUS}:channels:{channel}", fields=fields)  # type: ignore[arg-type]


async def send_message(message: Message, context: Any = None) -> None:
	context_data = None
	if context:
		context_data = dumps(context)
	logger.debug("Message to redis: %r", message)
	await send_message_msgpack(message.channel, message.to_msgpack(), context_data)


class MessageReader:  # pylint: disable=too-few-public-methods
	_info_suffix = b":info"

	def __init__(self, channels: Dict[str, Optional[StreamIdT]] = None, default_stream_id: str = "$") -> None:
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
		self._streams: Dict[bytes, StreamIdT] = {}
		self._key_prefix = f"{REDIS_PREFIX_MESSAGEBUS}:channels"

	def __repr__(self) -> str:
		return f"{self.__class__.__name__}({','.join(self._channels)})"

	__str__ = __repr__

	async def _update_streams(self) -> None:
		redis = await async_redis_client()
		stream_keys: List[bytes] = []
		for channel, redis_msg_id in self._channels.items():
			stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
			redis_msg_id = redis_msg_id or self._streams.get(stream_key) or self._default_stream_id
			if redis_msg_id == ">":
				last_delivered_id = await redis.hget(stream_key + self._info_suffix, "last-delivered-id")
				if last_delivered_id:
					redis_msg_id = last_delivered_id.decode("utf-8")
				else:
					redis_msg_id = "0"

			if not redis_msg_id:
				raise ValueError("No redis message id")  # pylint: disable=loop-invariant-statement

			self._streams[stream_key] = redis_msg_id
			stream_keys.append(stream_key)

		for stream_key in list(self._streams):
			if stream_key not in stream_keys:
				del self._streams[stream_key]
		logger.debug("%s updated streams: %s", self, self._streams)

	async def get_channel_names(self) -> List[str]:
		return list(self._channels)

	async def set_channels(self, channels: Dict[str, Optional[StreamIdT]]) -> None:
		self._channels = channels
		await self._update_streams()

	async def add_channels(self, channels: Dict[str, Optional[StreamIdT]]) -> None:
		self._channels.update(channels)
		await self._update_streams()

	async def remove_channels(self, channels: List[str]) -> None:
		for channel in channels:
			if channel in self._channels:
				del self._channels[channel]
		await self._update_streams()

	async def _get_stream_entries(self, redis: StrictRedis) -> dict:
		return await redis.xread(streams=self._streams, block=1000, count=10)  # type: ignore[arg-type]

	async def get_messages(self) -> AsyncGenerator[Tuple[str, Message, Any], None]:
		if not self._channels:
			raise ValueError("No channels to read from")

		_logger = logger
		try:
			await self._update_streams()
		except Exception as err:
			logger.error(err, exc_info=True)
			raise

		_logger.debug("%s: getting messages", self)

		redis = await async_redis_client()
		try:  # pylint: disable=too-many-nested-blocks
			while True:
				try:  # pylint: disable=loop-try-except-usage
					now = time()
					stream_entries = await self._get_stream_entries(redis)
					for stream_key, messages in stream_entries:
						last_redis_msg_id = ">"
						for message in messages:
							redis_msg_id = message[0].decode("utf-8")
							context = None
							context_data = message[1].get(b"context")
							if context_data:
								context = loads(context_data)
							msg = Message.from_msgpack(message[1][b"message"])
							_logger.debug("Message from redis: %r", msg)
							if msg.expires and msg.expires <= now:
								continue
							yield redis_msg_id, msg, context
							last_redis_msg_id = redis_msg_id
						self._streams[stream_key] = last_redis_msg_id
				except Exception as err:  # pylint: disable=broad-except
					_logger.error(err, exc_info=True)
					await sleep(3)
		except CancelledError:
			pass

	async def ack_message(self, channel: str, redis_msg_id: str) -> None:
		redis = await async_redis_client()
		stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
		if stream_key not in self._streams:
			raise ValueError(f"Invalid channel: {channel!r}")
		await redis.hset(stream_key + self._info_suffix, "last-delivered-id", redis_msg_id)


class ConsumerGroupMessageReader(MessageReader):
	def __init__(
		self, consumer_group: str, consumer_name: str, channels: Dict[str, Optional[StreamIdT]] = None, default_stream_id: str = "0"
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
		stream_keys: List[bytes] = []
		for channel, redis_msg_id in self._channels.items():
			stream_key = f"{self._key_prefix}:{channel}".encode("utf-8")
			try:  # pylint: disable=loop-try-except-usage
				await redis.xgroup_create(stream_key, self._consumer_group, id="0", mkstream=True)
			except ResponseError as err:  # pylint: disable=loop-invariant-statement
				if str(err).startswith("BUSYGROUP"):
					# Consumer Group name already exists
					pass
				else:
					raise

			self._streams[stream_key] = redis_msg_id or "0"
			stream_keys.append(stream_key)

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
		await redis.xack(stream_key, self._consumer_group, redis_msg_id)
