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

from opsicommon.messagebus import CONNECTION_SESSION_CHANNEL, Message  # type: ignore[import]

from opsiconfd.messagebus.redis import MAX_STREAM_LENGTH, ConsumerGroupMessageReader, MessageReader, send_message
from opsiconfd.redis import async_redis_client, get_redis_connections

from .utils import (  # noqa: F401
	Config,
	clean_redis,
	config,
)


async def test_message_reader_redis_connection() -> None:
	connections = get_redis_connections()
	channel = "host:test-channel"

	async def reader_task(reader: MessageReader) -> None:
		async for redis_id, message, context in reader.get_messages():
			print(redis_id, message, context)

	reader = MessageReader()
	await reader.set_channels(channels={channel: ">"})
	asyncio.create_task(reader_task(reader))
	await send_message(
		Message(id="00000000-0000-4000-8000-000000000001", type="test", sender="*", channel=channel), context=b"context_data1"
	)
	await asyncio.sleep(2)
	await reader.stop(wait=True)

	# All redis connections should be closed
	assert connections == get_redis_connections()


async def test_message_reader_user_channel(config: Config) -> None:  # noqa: F811
	connections = get_redis_connections()

	class MyMessageReader(MessageReader):
		def __init__(self, **kwargs: Any) -> None:
			self.received: list[tuple[str, Message, bytes]] = []
			super().__init__(**kwargs)

	async def reader_task(reader: MyMessageReader) -> None:
		async for redis_id, message, context in reader.get_messages():
			reader.received.append((redis_id, message, context))

	channel = "host:test-user-channel"

	redis = await async_redis_client()
	# Add some messages before reader starts reading
	await send_message(
		Message(id="00000000-0000-4000-8000-000000000001", type="test", sender="*", channel=channel), context=b"context_data1"
	)
	await send_message(
		Message(id="00000000-0000-4000-8000-000000000002", type="test", sender="*", channel=channel), context=b"context_data2"
	)

	# ID ">" means that we want to receive all undelivered messages.
	reader1 = MyMessageReader()
	await reader1.set_channels({channel: ">"})
	_reader_task1 = asyncio.create_task(reader_task(reader1))

	await send_message(
		Message(id="00000000-0000-4000-8000-000000000003", type="test", sender="*", channel=channel), context=b"context_data3"
	)
	await send_message(
		Message(id="00000000-0000-4000-8000-000000000004", type="test", sender="*", channel=channel), context=b"context_data4"
	)

	# Start another reader
	reader2 = MyMessageReader()
	await reader2.set_channels({channel: ">"})
	_reader_task2 = asyncio.create_task(reader_task(reader2))

	# Wait until readers have read all messages
	await asyncio.sleep(2)
	await reader1.stop(wait=True)
	await reader2.stop(wait=True)

	# Both readers should have received all messages
	for reader in reader1, reader2:
		assert len(reader.received) == 4
		for idx, received in enumerate(reader.received):
			assert received[1].type == "test"
			assert received[1].id == f"00000000-0000-4000-8000-00000000000{idx + 1}"
			assert received[2] == f"context_data{idx+1}".encode("utf-8")

	# We did not ACK any message, so last-delivered-id has to be None
	last_id = await redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "last-delivered-id")
	assert last_id is None

	# No reader running, add a message
	await send_message(
		Message(id="00000000-0000-4000-8000-000000000005", type="test", sender="*", channel=channel), context=b"context_data5"
	)

	# Start a reader again
	reader1 = MyMessageReader()
	await reader1.set_channels(channels={channel: ">"})
	_reader_task1 = asyncio.create_task(reader_task(reader1))

	await asyncio.sleep(1)
	await send_message(
		Message(id="00000000-0000-4000-8000-000000000006", type="test", sender="*", channel=channel), context=b"context_data6"
	)
	await asyncio.sleep(2)

	# Since we did not ACK any messages, the reader should receive all messages in the stream
	assert len(reader1.received) == 6
	for idx, received in enumerate(reader1.received):
		assert received[1].type == "test"
		assert received[1].id == f"00000000-0000-4000-8000-00000000000{idx + 1}"
		assert received[2] == f"context_data{idx+1}".encode("utf-8")
		# ACK message
		await reader1.ack_message(channel, received[0])
	last_acked_redis_id = reader1.received[5][0]

	await reader1.stop(wait=True)

	# last-delivered-id has to be the redis ID of the last ACKed message
	last_id = await redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "last-delivered-id")
	assert last_id
	assert last_id.decode("utf-8") == last_acked_redis_id

	# No reader running, add a message
	await send_message(
		Message(id="00000000-0000-4000-8000-000000000007", type="test", sender="*", channel=channel), context=b"context_data7"
	)

	# Start two readers again
	reader1 = MyMessageReader()
	await reader1.set_channels({channel: ">"})
	reader2 = MyMessageReader()
	await reader2.set_channels({"other-channel": ">"})
	_reader_task1 = asyncio.create_task(reader_task(reader1))
	await asyncio.sleep(1)
	_reader_task2 = asyncio.create_task(reader_task(reader2))
	await asyncio.sleep(1)
	await reader2.add_channels({channel: ">"})
	await asyncio.sleep(1)
	await send_message(
		Message(id="00000000-0000-4000-8000-000000000008", type="test", sender="*", channel=channel), context=b"context_data8"
	)
	await asyncio.sleep(2)

	await reader1.stop(wait=True)
	await reader2.stop(wait=True)

	# Both readers should have received all messages since last ACKed message
	for reader in reader1, reader2:
		assert len(reader.received) == 2

	# All redis connections should be closed
	assert connections == get_redis_connections()


async def test_message_reader_event_channel(config: Config) -> None:  # noqa: F811
	class MyMessageReader(MessageReader):
		def __init__(self, **kwargs: Any) -> None:
			self.received: list[tuple[str, Message, bytes]] = []
			super().__init__(**kwargs)

	async def reader_task(reader: MyMessageReader) -> None:
		async for redis_id, message, context in reader.get_messages():
			reader.received.append((redis_id, message, context))

	channel = "event:test_reader"
	redis = await async_redis_client()
	# Add some messages before reader starts reading
	await send_message(Message(id="00000000-0000-4000-8000-000000000001", type="test", sender="*", channel=channel))

	reader1 = MyMessageReader()
	await reader1.set_channels({channel: CONNECTION_SESSION_CHANNEL})
	_reader_task1 = asyncio.create_task(reader_task(reader1))

	await asyncio.sleep(1)
	assert await redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "reader-count") == b"1"

	await send_message(Message(id="00000000-0000-4000-8000-000000000002", type="test", sender="*", channel=channel))

	reader2 = MyMessageReader()
	await reader2.set_channels(channels={channel: CONNECTION_SESSION_CHANNEL})
	_reader_task2 = asyncio.create_task(reader_task(reader2))

	await asyncio.sleep(1)
	assert await redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "reader-count") == b"2"

	await send_message(Message(id="00000000-0000-4000-8000-000000000003", type="test", sender="*", channel=channel))

	reader3 = MyMessageReader()
	await reader3.set_channels(channels={channel: CONNECTION_SESSION_CHANNEL})
	_reader_task3 = asyncio.create_task(reader_task(reader3))

	# Re-set channels, to check if reader-count is handled correctly
	await reader2.set_channels(channels={channel: CONNECTION_SESSION_CHANNEL})

	await asyncio.sleep(1)
	assert await redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "reader-count") == b"3"

	await send_message(Message(id="00000000-0000-4000-8000-000000000004", type="test", sender="*", channel=channel))

	await asyncio.sleep(2)

	await reader1.stop()
	await reader2.stop()
	await reader3.stop()

	assert len(reader1.received) == 3
	assert len(reader2.received) == 2
	assert len(reader3.received) == 1

	await asyncio.sleep(1)

	assert await redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "reader-count") == b"0"


async def test_consumer_group_message_reader() -> None:
	class MyMessageReader(ConsumerGroupMessageReader):
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

	reader1 = MyMessageReader(consumer_group="service:config:jsonrpc", consumer_name="test:worker1")
	await reader1.set_channels({"service:config:jsonrpc": "0"})
	asyncio.create_task(reader_task(reader1))

	reader2 = MyMessageReader(consumer_group="service:config:jsonrpc", consumer_name="test:worker2")
	await reader2.set_channels({"service:config:jsonrpc": "0"})
	asyncio.create_task(reader_task(reader2))

	for idx in range(1, 101):
		await send_message(
			Message(id=f"00000000-0000-4000-8000-000000000{idx:03}", type="test", sender="*", channel="service:config:jsonrpc"),
			context=b"context_data",
		)

	await asyncio.sleep(3)
	await reader1.stop()
	await reader2.stop()
	await asyncio.sleep(2)

	assert len(reader1.received) >= 10
	assert len(reader2.received) >= 10
	assert len(reader1.received) + len(reader2.received) == 100

	assert reader1.received[0][1].type == "test"
	assert reader2.received[0][1].type == "test"

	assert "00000000-0000-4000-8000-000000000001" in (reader1.received[0][1].id, reader2.received[0][1].id)
	assert "00000000-0000-4000-8000-000000000100" in (reader1.received[-1][1].id, reader2.received[-1][1].id)

	# Add new message, do not ack messages for reader1
	for idx in range(101, 201):
		await send_message(
			Message(id=f"00000000-0000-4000-8000-000000000{idx:03}", type="test", sender="*", channel="service:config:jsonrpc"),
			context=b"context_data",
		)

	reader1 = MyMessageReader(consumer_group="service:config:jsonrpc", consumer_name="test:worker1")
	await reader1.set_channels({"service:config:jsonrpc": "0"})
	reader1.ack = False
	asyncio.create_task(reader_task(reader1))

	reader2 = MyMessageReader(consumer_group="service:config:jsonrpc", consumer_name="test:worker2")
	await reader2.set_channels({"service:config:jsonrpc": "0"})
	reader2.ack = True
	asyncio.create_task(reader_task(reader2))

	await asyncio.sleep(3)
	await reader1.stop()
	await reader2.stop()
	await asyncio.sleep(2)

	assert len(reader1.received) >= 10
	assert len(reader2.received) >= 10
	assert len(reader1.received) + len(reader2.received) == 100
	assert "00000000-0000-4000-8000-000000000101" in (reader1.received[0][1].id, reader2.received[0][1].id)
	assert "00000000-0000-4000-8000-000000000200" in (reader1.received[-1][1].id, reader2.received[-1][1].id)

	reader1_received_ids = [rcv[1].id for rcv in reader1.received]

	# Restart readers
	reader1 = MyMessageReader(consumer_group="service:config:jsonrpc", consumer_name="test:worker1")
	await reader1.set_channels({"service:config:jsonrpc": "0"})
	asyncio.create_task(reader_task(reader1))

	reader2 = MyMessageReader(consumer_group="service:config:jsonrpc", consumer_name="test:worker2")
	await reader2.set_channels({"service:config:jsonrpc": "0"})
	asyncio.create_task(reader_task(reader2))

	await asyncio.sleep(3)
	await reader1.stop()
	await reader2.stop()
	await asyncio.sleep(2)

	assert len(reader1.received) == len(reader1_received_ids)
	assert len(reader2.received) == 0

	assert sorted(reader1_received_ids) == sorted([rcv[1].id for rcv in reader1.received])

	# Restart readers
	reader1 = MyMessageReader(consumer_group="service:config:jsonrpc", consumer_name="test:worker1")
	await reader1.set_channels({"service:config:jsonrpc": "0"})
	asyncio.create_task(reader_task(reader1))

	reader2 = MyMessageReader(consumer_group="service:config:jsonrpc", consumer_name="test:worker2")
	await reader2.set_channels({"service:config:jsonrpc": "0"})
	asyncio.create_task(reader_task(reader2))

	await asyncio.sleep(3)
	await reader1.stop()
	await reader2.stop()
	await asyncio.sleep(2)

	assert len(reader1.received) == 0
	assert len(reader2.received) == 0


async def test_message_reader_survives_recreate_channel(config: Config) -> None:  # noqa: F811
	class MyMessageReader(MessageReader):
		def __init__(self, **kwargs: Any) -> None:
			self.received: list[tuple[str, Message, bytes]] = []
			super().__init__(**kwargs)

	async def reader_task(reader: MyMessageReader) -> None:
		async for redis_id, message, context in reader.get_messages():
			reader.received.append((redis_id, message, context))

	redis = await async_redis_client()
	reader = MyMessageReader()
	await reader.set_channels({"host:test-123": ">", "terminal:123": CONNECTION_SESSION_CHANNEL, "invalid": CONNECTION_SESSION_CHANNEL})
	asyncio.create_task(reader_task(reader))
	await asyncio.sleep(2)
	await send_message(Message(id="00000000-0000-4000-8000-000000000001", type="test", sender="*", channel="host:test-123"))
	await send_message(Message(id="00000000-0000-4000-8000-000000000002", type="test", sender="*", channel="terminal:123"))
	await asyncio.sleep(3)

	assert len(reader.received) == 2
	assert reader.received[0][1].id == "00000000-0000-4000-8000-000000000001"
	assert reader.received[1][1].id == "00000000-0000-4000-8000-000000000002"

	reader.received = []
	await redis.delete(f"{config.redis_key('messagebus')}:channels:terminal:123")
	assert (await redis.exists(f"{config.redis_key('messagebus')}:channels:terminal:123")) == 0

	await asyncio.sleep(1)
	await send_message(Message(id="00000000-0000-4000-8000-000000000003", type="test", sender="*", channel="host:test-123"))
	await send_message(Message(id="00000000-0000-4000-8000-000000000004", type="test", sender="*", channel="host:test-123"))
	await asyncio.sleep(3)

	assert len(reader.received) == 2
	assert reader.received[0][1].id == "00000000-0000-4000-8000-000000000003"
	assert reader.received[1][1].id == "00000000-0000-4000-8000-000000000004"
	reader.received = []

	await asyncio.sleep(1)
	await send_message(Message(id="00000000-0000-4000-8000-000000000005", type="test", sender="*", channel="host:test-123"))
	await send_message(Message(id="00000000-0000-4000-8000-000000000006", type="test", sender="*", channel="terminal:123"))
	assert (await redis.exists(f"{config.redis_key('messagebus')}:channels:terminal:123")) == 1
	await asyncio.sleep(3)

	assert len(reader.received) == 2
	assert reader.received[0][1].id == "00000000-0000-4000-8000-000000000005"
	assert reader.received[1][1].id == "00000000-0000-4000-8000-000000000006"

	await reader.stop()


async def test_message_trim_to_maxlen(config: Config) -> None:  # noqa: F811
	channel = "event:test_reader"
	redis = await async_redis_client()
	for count in range(0, 1500):
		await send_message(Message(id=f"00000000-0000-4000-8000-00000000{count:04}", type="test", sender="*", channel=channel))

	await asyncio.sleep(1)
	assert await redis.xlen(f"{config.redis_key('messagebus')}:channels:{channel}") < MAX_STREAM_LENGTH + 100
