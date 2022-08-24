# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.redis
"""

from asyncio.exceptions import CancelledError
from typing import Any, AsyncGenerator, Tuple

from msgpack import dumps, loads

from ..utils import async_redis_client
from .types import Message

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


async def consumer_group_message_reader(  # pylint: disable=too-many-locals
	channel: str, consumer_group: str, consumer_name: str, start_id: str = ">"
) -> AsyncGenerator[Tuple[Message, Any], bool]:
	stream = f"{PREFIX}:{channel}"
	b_consumer_group = consumer_group.encode("utf-8")
	redis = await async_redis_client()
	consumer_group_exists = False
	stream_exists = await redis.exists(stream)
	if stream_exists:
		for group in await redis.xinfo_groups(stream):
			if group["name"] == b_consumer_group:
				consumer_group_exists = True
				break

	if not consumer_group_exists:
		await redis.xgroup_create(stream, consumer_group, id="0", mkstream=not stream_exists)

	# pending = await redis.xpending(stream, consumer_group)
	# print(pending)
	# stream_info = await redis.xinfo_stream(stream)
	# print(stream_info)

	try:
		while True:
			data = await redis.xreadgroup(consumer_group, consumer_name, streams={stream: start_id}, block=1000, count=10)
			for stream_data in data:
				for dat in stream_data[1]:
					msg_id = dat[0]
					context = None
					context_data = dat[1].get(b"context")
					if context_data:
						context = loads(context_data)
					ack = yield Message.from_msgpack(dat[1][b"message"]), context
					if ack:
						await redis.xack(stream, consumer_group, msg_id)
	except CancelledError:
		pass
