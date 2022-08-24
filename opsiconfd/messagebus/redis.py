# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.redis
"""

from asyncio.exceptions import CancelledError
from typing import AsyncGenerator

from ..utils import async_redis_client
from .types import Message


async def send_message_msgpack(channel: str, msgpack_data: bytes) -> None:
	redis = await async_redis_client()
	await redis.xadd(channel, {"message": msgpack_data})


async def send_message(message: Message) -> None:
	await send_message_msgpack(message.channel, message.to_msgpack())


async def consumer_group_message_reader(
	channel: str, consumer_group: str, consumer_name: str, start_id: str = ">"
) -> AsyncGenerator[Message, bool]:
	b_consumer_group = consumer_group.encode("utf-8")
	redis = await async_redis_client()
	consumer_group_exists = False
	stream_exists = await redis.exists(channel)
	if stream_exists:
		for group in await redis.xinfo_groups(channel):
			if group["name"] == b_consumer_group:
				consumer_group_exists = True
				break

	if not consumer_group_exists:
		await redis.xgroup_create(channel, consumer_group, id="0", mkstream=not stream_exists)

	try:
		while True:
			data = await redis.xreadgroup(consumer_group, consumer_name, streams={channel: start_id}, block=1000, count=10)
			for stream in data:
				for dat in stream[1]:
					msg_id = dat[0]
					ack = yield Message.from_msgpack(dat[1].get(b"message"))
					if ack:
						await redis.xack(channel, consumer_group, msg_id)
	except CancelledError:
		pass
