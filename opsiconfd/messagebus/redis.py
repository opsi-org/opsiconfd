# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.redis
"""

from asyncio.exceptions import CancelledError
from time import time
from typing import Any, AsyncGenerator, Tuple

from msgpack import dumps, loads  # type: ignore[import]
from opsicommon.messagebus import Message  # type: ignore[import]

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
	def __init__(self, channel: str, start_id: str = "$"):
		"""
		ID "$" means that we only want new messages.
		"""
		self.stream = f"{PREFIX}:{channel}"
		self.start_id = start_id
		self.current_id = start_id

	async def get_messages(self) -> AsyncGenerator[Tuple[str, Message, Any], None]:
		try:
			redis = await async_redis_client()
			while True:
				now = time()
				stream_entries = await redis.xread(streams={self.stream: self.current_id}, block=1000, count=10)
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
		except CancelledError:
			pass


class ConsumerGroupMessageReader:
	def __init__(self, channel: str, consumer_group: str, consumer_name: str, start_id: str = "0"):
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

	async def ack_message(self, redis_id: str) -> None:
		redis = await async_redis_client()
		await redis.xack(self.stream, self.consumer_group, redis_id)

	async def get_messages(self) -> AsyncGenerator[Tuple[str, Message, Any], None]:
		await self._setup()
		try:
			redis = await async_redis_client()
			while True:
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
		except CancelledError:
			pass
