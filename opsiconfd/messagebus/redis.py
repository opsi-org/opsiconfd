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
from typing import Any, AsyncGenerator, Dict, Tuple

from aioredis.client import StreamIdT
from msgpack import dumps, loads  # type: ignore[import]
from opsicommon.messagebus import Message  # type: ignore[import]

from ..logging import logger
from ..utils import async_redis_client

PREFIX = "opsiconfd:messagebus"


async def send_message_msgpack(channel: str, msgpack_data: bytes, context_data: bytes = None) -> None:
	redis = await async_redis_client()
	fields = {"message": msgpack_data}
	if context_data:
		fields["context"] = context_data
	await redis.xadd(f"{PREFIX}:{channel}", fields=fields)  # type: ignore[arg-type]


async def send_message(message: Message, context: Any = None) -> None:
	context_data = None
	if context:
		context_data = dumps(context)
	await send_message_msgpack(message.channel, message.to_msgpack(), context_data)


class MessageReader:  # pylint: disable=too-few-public-methods
	_prefix = PREFIX
	_info_suffix = b":info"

	def __init__(self, channels: Dict[str, StreamIdT]):
		"""
		channels:
			A dict of channel names to stream IDs, where
			IDs indicate the last ID already seen.
			Special IDs:
			ID ">" means that we want to receive messages all undelivered messages.
			ID "$" means that we only want new messages (added after reader was started).
		"""
		self._channels = channels
		self._streams: Dict[bytes, StreamIdT] = {}

	async def _update_streams(self) -> None:
		redis = await async_redis_client()
		stream_keys = []
		for channel, redis_msg_id in self._channels.items():
			stream_key = f"{self._prefix}:{channel}".encode("utf-8")
			if not redis_msg_id or redis_msg_id == ">":
				last_delivered_id = await redis.hget(stream_key + self._info_suffix, "last-delivered-id")
				if last_delivered_id:
					redis_msg_id = last_delivered_id.decode("utf-8")
				else:
					redis_msg_id = "0"
			self._streams[stream_key] = redis_msg_id
			stream_keys.append(stream_key)

		for stream_key in list(self._streams):
			if stream_key not in stream_keys:
				del self._streams[stream_key]

	async def add_channel(self, channel: str, redis_msg_id: StreamIdT = ">") -> None:
		if channel in self._channels:
			raise ValueError("Channel already in use")
		self._channels[channel] = redis_msg_id
		await self._update_streams()

	async def remove_channel(self, channel: str) -> None:
		if channel not in self._channels:
			raise ValueError("Channel not in use")
		del self._channels[channel]
		await self._update_streams()

	async def get_messages(self) -> AsyncGenerator[Tuple[str, Message, Any], None]:
		await self._update_streams()

		redis = await async_redis_client()
		try:  # pylint: disable=too-many-nested-blocks
			while True:
				try:  # pylint: disable=loop-try-except-usage
					now = time()
					stream_entries = await redis.xread(streams=self._streams, block=1000, count=10)  # type: ignore[arg-type]
					for stream_key, messages in stream_entries:
						for message in messages:
							redis_msg_id = message[0].decode("utf-8")
							context = None
							context_data = message[1].get(b"context")
							if context_data:
								context = loads(context_data)
							msg = Message.from_msgpack(message[1][b"message"])
							if msg.expires and msg.expires <= now:
								continue
							yield redis_msg_id, msg, context
							self._streams[stream_key] = redis_msg_id  # pylint: disable=loop-invariant-statement
				except Exception as err:  # pylint: disable=broad-except
					logger.error(err, exc_info=True)
					await sleep(3)
		except CancelledError:
			pass

	async def ack_message(self, channel: str, redis_msg_id: str) -> None:
		redis = await async_redis_client()
		stream_key = f"{PREFIX}:{channel}".encode("utf-8")
		if stream_key not in self._streams:
			raise ValueError(f"Invalid channel: {channel!r}")
		await redis.hset(stream_key + self._info_suffix, "last-delivered-id", redis_msg_id)


class ConsumerGroupMessageReader:
	def __init__(self, channel: str, consumer_group: str, consumer_name: str, start_id: StreamIdT = "0"):
		"""
		ID ">" means that the consumer want to receive only messages that were never delivered to any other consumer.
		Any other ID, that is, 0 or any other valid ID will have the effect of returning entries that are pending
		for the consumer sending the command with IDs greater than the one provided.
		So basically if the ID is not ">", then the command will just let the client access its pending entries:
		messages delivered to it, but not yet acknowledged.
		"""
		self.stream = f"{PREFIX}:{channel}"
		self.consumer_group = consumer_group
		self.consumer_name = consumer_name
		self.start_id = start_id
		self.current_id = start_id

	async def _setup(self) -> None:
		redis = await async_redis_client()
		consumer_group_exists = False
		stream_exists = await redis.exists(self.stream)
		if stream_exists:
			consumer_group_utf8 = self.consumer_group.encode("utf-8")
			for group in await redis.xinfo_groups(self.stream):
				if group["name"] == consumer_group_utf8:
					consumer_group_exists = True
					break

		if not consumer_group_exists:
			await redis.xgroup_create(self.stream, self.consumer_group, id="0", mkstream=not stream_exists)

	async def get_messages(self) -> AsyncGenerator[Tuple[str, Message, Any], None]:
		await self._setup()
		redis = await async_redis_client()
		try:  # pylint: disable=too-many-nested-blocks
			while True:
				try:  # pylint: disable=loop-try-except-usage
					# stream_info = await redis.xinfo_stream(self.stream)
					# logger.trace(stream_info)
					# pending = await redis.xpending(self.stream, self.consumer_group)
					# logger.trace(pending)
					now = time()
					stream_entries = await redis.xreadgroup(
						self.consumer_group, self.consumer_name, streams={self.stream: self.current_id}, block=1000, count=10
					)
					for stream_entry in stream_entries:
						for message in stream_entry[1]:
							redis_id = message[0]
							context = None
							context_data = message[1].get(b"context")
							if context_data:
								context = loads(context_data)
							msg = Message.from_msgpack(message[1][b"message"])
							if msg.expires and msg.expires <= now:
								continue
							yield redis_id, msg, context
					# After the first read, fetch pending entires only
					self.current_id = ">"  # pylint: disable=loop-invariant-statement
				except Exception as err:  # pylint: disable=broad-except
					logger.error(err, exc_info=True)
					await sleep(3)
		except CancelledError:
			pass

	async def ack_message(self, redis_msg_id: str) -> None:
		redis = await async_redis_client()
		await redis.xack(self.stream, self.consumer_group, redis_msg_id)
