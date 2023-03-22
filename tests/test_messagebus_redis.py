# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.redis tests
"""

import asyncio
from typing import Any

import pytest
from opsicommon.messagebus import Message  # type: ignore[import]

from opsiconfd.messagebus.redis import (
	ConsumerGroupMessageReader,
	MessageReader,
	send_message,
	timestamp,
)

from .utils import (  # pylint: disable=unused-import
	Config,
	async_redis_client,
	clean_redis,
	config,
)


@pytest.mark.asyncio
async def test_message_reader_processing(config: Config) -> None:  # pylint: disable=redefined-outer-name
	class MyMessageReader(MessageReader):  # pylint: disable=too-few-public-methods
		def __init__(self, **kwargs: Any) -> None:
			self.received: list[tuple[str, Message, bytes]] = []
			super().__init__(**kwargs)

	async def reader_task(reader: MyMessageReader) -> None:
		async for redis_id, message, context in reader.get_messages():
			reader.received.append((redis_id, message, context))

	async with async_redis_client() as redis_client:
		reader = MyMessageReader(channels={"host:test-123": ">"})
		_reader_task = asyncio.create_task(reader_task(reader))
		await send_message(Message(id="1", type="test", sender="*", channel="host:test-123"), context=b"context_data")
		await asyncio.sleep(2)
		_reader_task.cancel()

		assert len(reader.received) == 1
		assert reader.received[0][1].type == "test"
		assert reader.received[0][1].id == "1"

		last_id = await redis_client.hget(
			f"{config.redis_key('messagebus')}:channels:host:test-123:info", "last-delivered-id"
		)  # pylint: disable=protected-access
		assert last_id is None

		await reader.ack_message("host:test-123", reader.received[0][0])

		last_id = await redis_client.hget(
			f"{config.redis_key('messagebus')}:channels:host:test-123:info", "last-delivered-id"
		)  # pylint: disable=protected-access
		assert last_id.decode("utf-8") == reader.received[0][0]  # type: ignore[union-attr]

		await send_message(Message(id="2", type="test", sender="*", channel="host:test-123"), context=b"context_data")
		await send_message(Message(id="3", type="test", sender="*", channel="host:test-123"), context=b"context_data")

		reader = MyMessageReader(channels={"host:test-123": ">"})
		_reader_task = asyncio.create_task(reader_task(reader))
		await send_message(Message(id="4", type="test", sender="*", channel="host:test-123"), context=b"context_data")
		await send_message(Message(id="5", type="test", sender="*", channel="other-channel"))

		await asyncio.sleep(2)

		assert len(reader.received) == 3
		assert reader.received[0][1].id == "2"
		assert reader.received[1][1].id == "3"
		assert reader.received[2][1].id == "4"

		await reader.ack_message("host:test-123", reader.received[2][0])
		last_id = await redis_client.hget(
			f"{config.redis_key('messagebus')}:channels:host:test-123:info", "last-delivered-id"
		)  # pylint: disable=protected-access
		assert last_id.decode("utf-8") == reader.received[2][0]  # type: ignore[union-attr]
		reader.received = []

		await reader.add_channels({"other-channel": ">"})
		await asyncio.sleep(2)

		assert len(reader.received) == 1
		assert reader.received[0][1].id == "5"
		assert reader.received[0][1].channel == "other-channel"

		reader.received = []
		await reader.remove_channels(["other-channel"])
		await asyncio.sleep(2)
		await send_message(Message(id="6", type="test", sender="*", channel="host:test-123", expires=timestamp() + 5000))
		await send_message(Message(id="7", type="test", sender="*", channel="host:test-123", expires=timestamp()))
		await send_message(Message(id="8", type="test", sender="*", channel="other-channel"))
		await asyncio.sleep(2)

		assert len(reader.received) == 1
		assert reader.received[0][1].id == "6"

		await reader.stop()


@pytest.mark.asyncio
async def test_consumer_group_message_reader() -> None:  # pylint: disable=redefined-outer-name,too-many-statements
	class MyMessageReader(ConsumerGroupMessageReader):  # pylint: disable=too-few-public-methods
		def __init__(self, **kwargs: Any) -> None:
			self.ack = True
			self.received: list[tuple[str, Message, bytes]] = []
			super().__init__(**kwargs)

	async def reader_task(reader: MyMessageReader) -> None:
		async for redis_id, message, context in reader.get_messages():
			reader.received.append((redis_id, message, context))
			await asyncio.sleep(0.01)
			if reader.ack:
				await reader.ack_message(message.channel, redis_id)

	reader1 = MyMessageReader(
		consumer_group="service:config:jsonrpc", consumer_name="test:worker1", channels={"service:config:jsonrpc": "0"}
	)
	asyncio.create_task(reader_task(reader1))

	reader2 = MyMessageReader(
		consumer_group="service:config:jsonrpc", consumer_name="test:worker2", channels={"service:config:jsonrpc": "0"}
	)
	asyncio.create_task(reader_task(reader2))

	for idx in range(1, 101):
		await send_message(Message(id=str(idx), type="test", sender="*", channel="service:config:jsonrpc"), context=b"context_data")

	await asyncio.sleep(3)
	await reader1.stop()
	await reader2.stop()
	await asyncio.sleep(2)

	assert len(reader1.received) >= 10
	assert len(reader2.received) >= 10
	assert len(reader1.received) + len(reader2.received) == 100

	assert reader1.received[0][1].type == "test"
	assert reader2.received[0][1].type == "test"

	assert "1" in (reader1.received[0][1].id, reader2.received[0][1].id)
	assert "100" in (reader1.received[-1][1].id, reader2.received[-1][1].id)

	# Add new message, do not ack messages for reader1
	for idx in range(101, 201):
		await send_message(Message(id=str(idx), type="test", sender="*", channel="service:config:jsonrpc"), context=b"context_data")

	reader1 = MyMessageReader(
		consumer_group="service:config:jsonrpc", consumer_name="test:worker1", channels={"service:config:jsonrpc": "0"}
	)
	reader1.ack = False
	asyncio.create_task(reader_task(reader1))

	reader2 = MyMessageReader(
		consumer_group="service:config:jsonrpc", consumer_name="test:worker2", channels={"service:config:jsonrpc": "0"}
	)
	reader2.ack = True
	asyncio.create_task(reader_task(reader2))

	await asyncio.sleep(3)
	await reader1.stop()
	await reader2.stop()
	await asyncio.sleep(2)

	assert len(reader1.received) >= 10
	assert len(reader2.received) >= 10
	assert len(reader1.received) + len(reader2.received) == 100
	assert "101" in (reader1.received[0][1].id, reader2.received[0][1].id)
	assert "200" in (reader1.received[-1][1].id, reader2.received[-1][1].id)

	reader1_received_ids = [rcv[1].id for rcv in reader1.received]

	# Restart readers
	reader1 = MyMessageReader(
		consumer_group="service:config:jsonrpc", consumer_name="test:worker1", channels={"service:config:jsonrpc": "0"}
	)
	asyncio.create_task(reader_task(reader1))

	reader2 = MyMessageReader(
		consumer_group="service:config:jsonrpc", consumer_name="test:worker2", channels={"service:config:jsonrpc": "0"}
	)
	asyncio.create_task(reader_task(reader2))

	await asyncio.sleep(3)
	await reader1.stop()
	await reader2.stop()
	await asyncio.sleep(2)

	assert len(reader1.received) == len(reader1_received_ids)
	assert len(reader2.received) == 0

	assert sorted(reader1_received_ids) == sorted([rcv[1].id for rcv in reader1.received])

	# Restart readers
	reader1 = MyMessageReader(
		consumer_group="service:config:jsonrpc", consumer_name="test:worker1", channels={"service:config:jsonrpc": "0"}
	)
	asyncio.create_task(reader_task(reader1))

	reader2 = MyMessageReader(
		consumer_group="service:config:jsonrpc", consumer_name="test:worker2", channels={"service:config:jsonrpc": "0"}
	)
	asyncio.create_task(reader_task(reader2))

	await asyncio.sleep(3)
	await reader1.stop()
	await reader2.stop()
	await asyncio.sleep(2)

	assert len(reader1.received) == 0
	assert len(reader2.received) == 0


@pytest.mark.asyncio
async def test_message_reader_survives_recreate_channel(config: Config) -> None:  # pylint: disable=redefined-outer-name
	class MyMessageReader(MessageReader):  # pylint: disable=too-few-public-methods
		def __init__(self, **kwargs: Any) -> None:
			self.received: list[tuple[str, Message, bytes]] = []
			super().__init__(**kwargs)

	async def reader_task(reader: MyMessageReader) -> None:
		async for redis_id, message, context in reader.get_messages():
			reader.received.append((redis_id, message, context))

	async with async_redis_client() as redis_client:
		reader = MyMessageReader(channels={"host:test-123": ">", "terminal:123": "$", "invalid": "$"})
		asyncio.create_task(reader_task(reader))
		await asyncio.sleep(2)
		await send_message(Message(id="1", type="test", sender="*", channel="host:test-123"))
		await send_message(Message(id="2", type="test", sender="*", channel="terminal:123"))
		await asyncio.sleep(3)

		assert len(reader.received) == 2
		assert reader.received[0][1].id == "1"
		assert reader.received[1][1].id == "2"

		reader.received = []
		await redis_client.delete(f"{config.redis_key('messagebus')}:channels:terminal:123")
		assert (await redis_client.exists(f"{config.redis_key('messagebus')}:channels:terminal:123")) == 0

		await asyncio.sleep(1)
		await send_message(Message(id="3", type="test", sender="*", channel="host:test-123"))
		await send_message(Message(id="4", type="test", sender="*", channel="host:test-123"))
		await asyncio.sleep(3)

		assert len(reader.received) == 2
		assert reader.received[0][1].id == "3"
		assert reader.received[1][1].id == "4"
		reader.received = []

		await asyncio.sleep(1)
		await send_message(Message(id="5", type="test", sender="*", channel="host:test-123"))
		await send_message(Message(id="6", type="test", sender="*", channel="terminal:123"))
		assert (await redis_client.exists(f"{config.redis_key('messagebus')}:channels:terminal:123")) == 1
		await asyncio.sleep(3)

		assert len(reader.received) == 2
		assert reader.received[0][1].id == "5"
		assert reader.received[1][1].id == "6"

		await reader.stop()
