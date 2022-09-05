# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.redis tests
"""

import asyncio
from typing import Any, List, Tuple

import pytest
from opsicommon.messagebus import Message  # type: ignore[import]

from opsiconfd.messagebus.redis import MessageReader, send_message

from .utils import async_redis_client, clean_redis  # pylint: disable=unused-import


@pytest.mark.asyncio
async def test_message_reader() -> None:  # pylint: disable=redefined-outer-name
	async with async_redis_client() as redis_client:
		class MyMessageReader(MessageReader):  # pylint: disable=too-few-public-methods
			def __init__(self, **kwargs: Any) -> None:
				self.received: List[Tuple[str, Message, bytes]] = []
				super().__init__(**kwargs)

		async def reader_task(reader: MyMessageReader) -> None:
			async for redis_id, message, context in reader.get_messages():
				reader.received.append((redis_id, message, context))

		reader = MyMessageReader(channel="host:test-123", start_id="auto")
		_reader_task = asyncio.create_task(reader_task(reader))
		await send_message(Message(id="1", type="test", sender="*", channel="host:test-123"), context=b"context_data")
		await asyncio.sleep(1)
		_reader_task.cancel()
		assert len(reader.received) == 1
		assert reader.received[0][1].type == "test"
		assert reader.received[0][1].id == "1"

		last_id = await redis_client.hget(reader.stream_info_key, "last-delivered-id")
		assert last_id == reader.received[0][0]

		await send_message(Message(id="2", type="test", sender="*", channel="host:test-123"), context=b"context_data")
		await send_message(Message(id="3", type="test", sender="*", channel="host:test-123"), context=b"context_data")

		reader = MyMessageReader(channel="host:test-123", start_id="auto")
		_reader_task = asyncio.create_task(reader_task(reader))
		await send_message(Message(id="4", type="test", sender="*", channel="host:test-123"), context=b"context_data")
		await asyncio.sleep(1)
		_reader_task.cancel()
		assert len(reader.received) == 3  # type: ignore[attr-defined]  # pylint: disable=no-member
		assert reader.received[0][1].id == "2"
		assert reader.received[1][1].id == "3"
		assert reader.received[2][1].id == "4"

		last_id = await redis_client.hget(reader.stream_info_key, "last-delivered-id")
		assert last_id == reader.received[2][0]
