# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus tests
"""

import random
from random import randbytes
from time import sleep, time
from unittest.mock import patch
from uuid import uuid4

import pytest
from opsicommon.messagebus import (  # type: ignore[import]
	CONNECTION_SESSION_CHANNEL,
	CONNECTION_USER_CHANNEL,
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionRequestMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	TerminalDataReadMessage,
	TerminalDataWriteMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
	TerminalResizeEventMessage,
	TerminalResizeRequestMessage,
	TraceRequestMessage,
	TraceResponseMessage,
	timestamp,
)
from opsicommon.objects import UnicodeConfig

from opsiconfd.redis import get_redis_connections, ip_address_to_redis_key
from opsiconfd.session import OPSISession, session_manager
from opsiconfd.utils import asyncio_create_task, compress_data, decompress_data

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	Redis,
	WebSocketMessageReader,
	async_redis_client,
	clean_mysql,
	clean_redis,
	client_jsonrpc,
	config,
	sync_redis_client,
	test_client,
)


@pytest.mark.parametrize("compression", ("", "lz4", "gzip"))
def test_messagebus_compression(test_client: OpsiconfdTestClient, compression: str) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	# "with test_client" will run startup and shutdown event handler
	# https://fastapi.tiangolo.com/advanced/testing-events/
	with test_client:
		with test_client.websocket_connect(f"/messagebus/v1?compression={compression}") as websocket:
			with WebSocketMessageReader(websocket, decode=False) as reader:
				reader.wait_for_message()
				next(reader.get_raw_messages())
				jsonrpc_request_message = JSONRPCRequestMessage(
					sender=CONNECTION_USER_CHANNEL, channel="service:config:jsonrpc", rpc_id="1", method="accessControl_userIsAdmin"
				)
				data = jsonrpc_request_message.to_msgpack()
				if compression:
					data = compress_data(data, compression)
				websocket.send_bytes(data)

				reader.wait_for_message()
				raw_data = next(reader.get_raw_messages())
				if compression:
					raw_data = decompress_data(raw_data, compression)  # type: ignore[arg-type]
				jsonrpc_response_message = Message.from_msgpack(raw_data)  # type: ignore[arg-type]

				assert isinstance(jsonrpc_response_message, JSONRPCResponseMessage)
				assert jsonrpc_response_message.rpc_id == jsonrpc_request_message.rpc_id
				assert jsonrpc_response_message.result is True
				assert jsonrpc_response_message.error is None


def test_session_channel_subscription(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	connections = get_redis_connections()
	with test_client.websocket_connect("/messagebus/v1") as websocket:
		with WebSocketMessageReader(websocket, decode=False) as reader:
			reader.wait_for_message(count=1)
			message = Message.from_msgpack(next(reader.get_raw_messages()))
			assert isinstance(message, ChannelSubscriptionEventMessage)
			assert len(message.subscribed_channels) == 2
			print(message.subscribed_channels)
			user_channel = None
			session_channel = None
			for channel in message.subscribed_channels:
				if channel.startswith("session:"):
					session_channel = channel
				else:
					user_channel = channel
			assert user_channel == f"user:{ADMIN_USER}"
			assert session_channel

			message = Message(
				type="test", sender=CONNECTION_USER_CHANNEL, channel=session_channel, id="00000000-0000-4000-8000-000000000001"
			)
			websocket.send_bytes(message.to_msgpack())
			message = Message(type="test", sender=CONNECTION_USER_CHANNEL, channel=user_channel, id="00000000-0000-4000-8000-000000000002")
			websocket.send_bytes(message.to_msgpack())

			reader.wait_for_message(count=2)
			messages = [Message.from_msgpack(msg) for msg in list(reader.get_raw_messages())]
			assert len(messages) == 2

			assert sorted([msg.id for msg in messages]) == ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"]

			# Subscribe for 2 new session channels
			other_channel1 = "session:11111111-1111-1111-1111-111111111111"
			other_channel2 = "session:22222222-2222-2222-2222-222222222222"
			message = ChannelSubscriptionRequestMessage(
				sender=CONNECTION_USER_CHANNEL, channel="service:messagebus", channels=[other_channel1, other_channel2], operation="add"
			)
			websocket.send_bytes(message.to_msgpack())

			reader.wait_for_message(count=1)
			message = Message.from_msgpack(next(reader.get_raw_messages()))
			assert isinstance(message, ChannelSubscriptionEventMessage)
			assert len(message.subscribed_channels) == 4

			assert user_channel in message.subscribed_channels
			assert session_channel in message.subscribed_channels
			assert other_channel1 in message.subscribed_channels
			assert other_channel2 in message.subscribed_channels

			message = Message(
				type="test", sender=CONNECTION_USER_CHANNEL, channel=session_channel, id="00000000-0000-4000-8000-000000000003"
			)
			websocket.send_bytes(message.to_msgpack())
			message = Message(type="test", sender=CONNECTION_USER_CHANNEL, channel=user_channel, id="00000000-0000-4000-8000-000000000004")
			websocket.send_bytes(message.to_msgpack())
			message = Message(
				type="test", sender=CONNECTION_USER_CHANNEL, channel=other_channel1, id="00000000-0000-4000-8000-000000000005"
			)
			websocket.send_bytes(message.to_msgpack())
			message = Message(
				type="test", sender=CONNECTION_USER_CHANNEL, channel=other_channel2, id="00000000-0000-4000-8000-000000000006"
			)
			websocket.send_bytes(message.to_msgpack())

			reader.wait_for_message(count=4)
			messages = [Message.from_msgpack(msg) for msg in list(reader.get_raw_messages())]
			assert len(messages) == 4
			assert sorted([msg.id for msg in messages]) == [
				"00000000-0000-4000-8000-000000000003",
				"00000000-0000-4000-8000-000000000004",
				"00000000-0000-4000-8000-000000000005",
				"00000000-0000-4000-8000-000000000006",
			]
	# All redis connections should be closed
	assert connections == get_redis_connections()


def test_messagebus_multi_client_session_and_user_channel(  # pylint: disable=too-many-locals,redefined-outer-name
	config: Config,
	test_client: OpsiconfdTestClient,
) -> None:
	host_id = "msgbus-test-client.opsi.test"
	host_key = "92aa768a259dec1856013c4e458507d5"
	channel = f"host:{host_id}"

	def wait_for_reader_count(redis: Redis, channel: str, count: int, timeout: int = 5) -> None:
		print(f"Wait for reader count: {count}, timeout: {timeout}")
		reader_count = 0
		for _ in range(timeout):
			reader_count = int(redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "reader-count") or 0)
			print("Reader count:", reader_count)
			if reader_count == count:
				return
			sleep(1)
		raise RuntimeError(f"Timeout while waiting for reader count {count}")

	with sync_redis_client() as redis:
		assert redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "reader-count") is None

		with client_jsonrpc(test_client, "", host_id=host_id, host_key=host_key):
			test_client.auth = (host_id, host_key)
			with (
				test_client.websocket_connect("/messagebus/v1") as websocket1,
				test_client.websocket_connect("/messagebus/v1") as websocket2,
			):
				with WebSocketMessageReader(websocket1) as reader1, WebSocketMessageReader(websocket2) as reader2:
					for reader, _websocket in ((reader1, websocket1), (reader2, websocket2)):
						reader.wait_for_message(count=1)
						messages = list(reader.get_messages())
						assert messages[0]["type"] == "channel_subscription_event"  # type: ignore[call-overload]
						assert len(messages[0]["subscribed_channels"]) == 2  # type: ignore[call-overload]
						assert channel in messages[0]["subscribed_channels"]  # type: ignore[call-overload]

					wait_for_reader_count(redis, channel, 2)
					message = Message(
						type="test_multi_client", sender=CONNECTION_USER_CHANNEL, channel=channel, id="00000000-0000-4000-8000-000000000001"
					)
					websocket1.send_bytes(message.to_msgpack())
					for reader in (reader1, reader2):
						reader.wait_for_message(count=1)
						messages = list(reader.get_messages())
						# print(messages)
						assert len(messages) == 1
						assert messages[0]["type"] == "test_multi_client"
						assert messages[0]["id"] == "00000000-0000-4000-8000-000000000001"

					sleep(1)
					# print(list(reader2.get_messages()))
					with test_client.websocket_connect("/messagebus/v1") as websocket3:
						with WebSocketMessageReader(websocket3) as reader3:
							reader3.wait_for_message(count=1)
							messages = list(reader3.get_messages())
							assert messages[0]["type"] == "channel_subscription_event"
							assert len(messages[0]["subscribed_channels"]) == 2
							assert channel in messages[0]["subscribed_channels"]  # type: ignore[call-overload]

							wait_for_reader_count(redis, channel, 3)
							message = Message(
								type="test_multi_client",
								sender=CONNECTION_USER_CHANNEL,
								channel=channel,
								id="00000000-0000-4000-8000-000000000002",
							)
							websocket1.send_bytes(message.to_msgpack())
							for reader in (reader1, reader2, reader3):
								reader.wait_for_message(count=1)
								messages = list(reader.get_messages())
								assert len(messages) == 1
								assert messages[0]["type"] == "test_multi_client"  # type: ignore[call-overload]
								assert messages[0]["id"] == "00000000-0000-4000-8000-000000000002"  # type: ignore[call-overload]

					wait_for_reader_count(redis, channel, 2)

			wait_for_reader_count(redis, channel, 0)


def test_messagebus_multi_client_service_channel(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with (
		test_client.websocket_connect("/messagebus/v1") as websocket1,
		test_client.websocket_connect("/messagebus/v1") as websocket2,
		test_client.websocket_connect("/messagebus/v1") as websocket3,
	):
		with (
			WebSocketMessageReader(websocket1, print_raw_data=256) as reader1,
			WebSocketMessageReader(websocket2, print_raw_data=256) as reader2,
			WebSocketMessageReader(websocket3, print_raw_data=256) as reader3,
		):
			for reader, websocket in ((reader1, websocket1), (reader2, websocket2), (reader3, websocket3)):
				reader.wait_for_message(count=1)
				messages = list(reader.get_messages())
				assert messages[0]["type"] == "channel_subscription_event"  # type: ignore[call-overload]
				assert len(messages[0]["subscribed_channels"]) == 2  # type: ignore[call-overload]

				message = ChannelSubscriptionRequestMessage(
					sender=CONNECTION_USER_CHANNEL, channel="service:messagebus", channels=["service:config:jsonrpc"], operation="add"
				)
				websocket.send_bytes(message.to_msgpack())

				reader.wait_for_message(count=1)
				messages = list(reader.get_messages())
				assert messages[0]["type"] == "channel_subscription_event"  # type: ignore[call-overload]
				assert len(messages[0]["subscribed_channels"]) == 3  # type: ignore[call-overload]

			print("Initialization completed, sending messages")

			count = 50
			for rpc_id in range(count):
				jsonrpc_request_message = JSONRPCRequestMessage(
					sender=CONNECTION_USER_CHANNEL, channel="service:config:jsonrpc", rpc_id=str(rpc_id), method="accessControl_userIsAdmin"
				)
				websocket = random.choice((websocket1, websocket2, websocket3))
				websocket.send_bytes(jsonrpc_request_message.to_msgpack())

			print("Receiving messages")
			all_messages = []
			for reader, websocket in ((reader1, websocket1), (reader2, websocket2), (reader3, websocket3)):
				reader.wait_for_message(count=50, timeout=5.0, error_on_timeout=False)
				messages = list(reader.get_messages())
				# Every reader should get some messages
				assert len(messages) > 0
				all_messages.extend(messages)

			# Sum of all messages should be count
			assert len(all_messages) == count

	with (
		test_client.websocket_connect("/messagebus/v1") as websocket1,
		test_client.websocket_connect("/messagebus/v1") as websocket2,
		test_client.websocket_connect("/messagebus/v1") as websocket3,
	):
		with (
			WebSocketMessageReader(websocket1) as reader1,
			WebSocketMessageReader(websocket2) as reader2,
			WebSocketMessageReader(websocket3) as reader3,
		):
			for reader, websocket in ((reader1, websocket1), (reader2, websocket2), (reader3, websocket3)):
				reader.wait_for_message(count=1)
				messages = list(reader.get_messages())
				assert messages[0]["type"] == "channel_subscription_event"  # type: ignore[call-overload]
				assert len(messages[0]["subscribed_channels"]) == 2  # type: ignore[call-overload]

				# All messages are ACKed, no new messages expected
				with pytest.raises(RuntimeError, match="Timed out while waiting"):
					reader.wait_for_message(count=1, timeout=1)


def test_messagebus_jsonrpc(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	host_id = "msgbus-test-client.opsi.test"
	host_key = "92aa768a259dec1856013c4e458507d5"
	with client_jsonrpc(test_client, "", host_id=host_id, host_key=host_key):
		test_client.auth = (host_id, host_key)
		with test_client:
			with test_client.websocket_connect("/messagebus/v1") as websocket:
				with WebSocketMessageReader(websocket) as reader:
					reader.running.wait(3.0)
					sleep(2)
					reader.wait_for_message(count=1)
					assert next(reader.get_messages())["type"] == "channel_subscription_event"  # type: ignore[call-overload]
					jsonrpc_request_message1 = JSONRPCRequestMessage(
						sender=CONNECTION_USER_CHANNEL, channel="service:config:jsonrpc", rpc_id="1", method="accessControl_userIsAdmin"
					)
					websocket.send_bytes(jsonrpc_request_message1.to_msgpack())
					jsonrpc_request_message2 = JSONRPCRequestMessage(
						sender=CONNECTION_USER_CHANNEL,
						channel="service:config:jsonrpc",
						rpc_id="2",
						method="config_create",
						params=("test", "descr"),
					)
					websocket.send_bytes(jsonrpc_request_message2.to_msgpack())
					jsonrpc_request_message3 = JSONRPCRequestMessage(
						sender=CONNECTION_USER_CHANNEL, channel="service:config:jsonrpc", rpc_id="3", method="invalid", params=(1, 2, 3)
					)
					websocket.send_bytes(jsonrpc_request_message3.to_msgpack())
					jsonrpc_request_message4 = JSONRPCRequestMessage(
						sender=CONNECTION_USER_CHANNEL,
						channel="service:config:jsonrpc",
						rpc_id="4",
						method="hostControl_start",
						params=("client.opsi.test",),
					)
					websocket.send_bytes(jsonrpc_request_message4.to_msgpack())

					reader.wait_for_message(count=4, timeout=10.0)

					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					# for res in responses:
					# 	print(res.to_dict())

					assert isinstance(responses[0], JSONRPCResponseMessage)
					assert responses[0].rpc_id == jsonrpc_request_message1.rpc_id
					assert responses[0].result is False
					assert responses[0].error is None

					assert isinstance(responses[1], JSONRPCResponseMessage)
					assert responses[1].rpc_id == jsonrpc_request_message2.rpc_id
					assert responses[1].result is None
					assert responses[1].error is None

					assert isinstance(responses[2], JSONRPCResponseMessage)
					assert responses[2].rpc_id == jsonrpc_request_message3.rpc_id
					assert responses[2].result is None
					assert responses[2].error == {
						"code": 0,
						"message": "Invalid method 'invalid'",
						"data": {"class": "ValueError", "details": None},
					}

					assert isinstance(responses[3], JSONRPCResponseMessage)
					assert responses[3].rpc_id == jsonrpc_request_message4.rpc_id
					assert responses[3].result is None
					assert responses[3].error == {
						"code": 0,
						"message": "Opsi service permission error: No permission for method 'hostControl_start'",
						"data": {"class": "OpsiServicePermissionError", "details": None},
					}


def test_messagebus_terminal(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client as client:
		with client.websocket_connect("/messagebus/v1") as websocket:
			with WebSocketMessageReader(websocket, print_raw_data=500) as reader:
				reader.wait_for_message(count=1)
				message = Message.from_dict(next(reader.get_messages()))
				assert isinstance(message, ChannelSubscriptionEventMessage)

				terminal_id = str(uuid4())
				terminal_open_request = TerminalOpenRequestMessage(
					sender=CONNECTION_USER_CHANNEL, channel="service:config:terminal", terminal_id=terminal_id, rows=20, cols=150
				)
				websocket.send_bytes(terminal_open_request.to_msgpack())

				reader.wait_for_message(count=2)
				responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
				assert isinstance(responses[0], TerminalOpenEventMessage)
				assert responses[0].rows
				assert responses[0].cols
				assert responses[0].terminal_id == terminal_id
				assert responses[0].back_channel
				back_channel = responses[0].back_channel

				assert isinstance(responses[1], TerminalDataReadMessage)
				assert responses[1].terminal_id == terminal_id
				assert responses[1].data

				terminal_data_write = TerminalDataWriteMessage(
					sender=CONNECTION_USER_CHANNEL, channel=back_channel, terminal_id=terminal_id, data=b"echo test\r"
				)
				websocket.send_bytes(terminal_data_write.to_msgpack())

				reader.wait_for_message(count=1)
				responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
				assert isinstance(responses[0], TerminalDataReadMessage)
				assert responses[0].terminal_id == terminal_id
				assert "echo test\r\n" in responses[0].data.decode("utf-8")

				terminal_resize_request = TerminalResizeRequestMessage(
					sender=CONNECTION_USER_CHANNEL, channel=back_channel, terminal_id=terminal_id, rows=10, cols=160
				)
				websocket.send_bytes(terminal_resize_request.to_msgpack())

				reader.wait_for_message(count=2)
				responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]

				resize_message = [msg for msg in responses if isinstance(msg, TerminalResizeEventMessage)][0]
				data_message = [msg for msg in responses if isinstance(msg, TerminalDataReadMessage)][0]

				assert resize_message.terminal_id == terminal_id
				assert resize_message.rows == 10
				assert resize_message.cols == 160

				assert data_message.terminal_id == terminal_id


def test_trace(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with test_client.websocket_connect("/messagebus/v1") as websocket:
		with WebSocketMessageReader(websocket) as reader:
			reader.wait_for_message(count=1)
			next(reader.get_messages())

			payload = randbytes(16 * 1024)
			message1 = TraceRequestMessage(sender=CONNECTION_USER_CHANNEL, channel=CONNECTION_SESSION_CHANNEL, payload=payload, trace={})
			assert round(message1.created / 1000) == round(time())
			message1.trace["sender_ws_send"] = int(time() * 1000)
			websocket.send_bytes(message1.to_msgpack())

			reader.wait_for_message(count=1)
			message2 = TraceRequestMessage.from_dict(next(reader.get_messages()))
			message2.trace["recipient_ws_receive"] = timestamp()
			assert message2.created == message1.created

			message3 = TraceResponseMessage(
				sender=CONNECTION_USER_CHANNEL,
				channel=CONNECTION_SESSION_CHANNEL,
				ref_id=message2.id,
				req_trace=message2.trace,
				trace={"sender_ws_send": timestamp()},
				payload=message2.payload,
			)
			websocket.send_bytes(message3.to_msgpack())

			reader.wait_for_message(count=1, timeout=10)
			message4 = TraceResponseMessage.from_dict(next(reader.get_messages()))
			message4.trace["recipient_ws_receive"] = timestamp()

			assert message4.ref_id == message1.id
			assert message4.payload == message1.payload
			trc = message4.req_trace
			assert (
				trc["sender_ws_send"]
				<= trc["broker_ws_receive"]
				<= trc["broker_redis_send"]
				<= trc["broker_redis_receive"]
				<= trc["broker_ws_send"]
				<= trc["recipient_ws_receive"]
			)
			trc = message4.trace
			assert (
				trc["sender_ws_send"]
				<= trc["broker_ws_receive"]
				<= trc["broker_redis_send"]
				<= trc["broker_redis_receive"]
				<= trc["broker_ws_send"]
				<= trc["recipient_ws_receive"]
			)


def test_messagebus_events(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with test_client.websocket_connect("/messagebus/v1") as websocket:
		with WebSocketMessageReader(websocket) as reader:
			message = ChannelSubscriptionRequestMessage(
				sender=CONNECTION_USER_CHANNEL, channel="service:messagebus", channels=["event:config_created"], operation="add"
			)
			websocket.send_bytes(message.to_msgpack())
			reader.wait_for_message(count=2)
			list(reader.get_messages())

			conf = UnicodeConfig("test.config")
			rpc = {"id": 12345, "method": "config_createObjects", "params": [conf.to_hash()]}
			res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
			res.raise_for_status()
			result = res.json()
			assert result["id"] == rpc["id"]
			assert result["error"] is None
			assert result["result"] is None

			reader.wait_for_message(count=1)
			msg = next(reader.get_messages())
			assert msg["type"] == "event"
			assert msg["channel"] == "event:config_created"
			assert msg["event"] == "config_created"
			assert msg["data"] == {"id": "test.config"}


@pytest.mark.asyncio
async def test_messagebus_close_on_session_deleted(  # pylint: disable=too-many-locals,redefined-outer-name
	config: Config,
	test_client: OpsiconfdTestClient,
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	session_manager._session_check_interval = 1  # pylint: disable=protected-access
	session_manager._session_store_interval_min = 1  # pylint: disable=protected-access
	asyncio_create_task(session_manager.manager_task())
	try:
		with patch("opsiconfd.messagebus.websocket.MessagebusWebsocket._update_session_interval", 1.0):
			async with async_redis_client() as redis:
				with test_client.websocket_connect("/messagebus/v1") as websocket:
					session: OPSISession = websocket.scope["session"]
					with WebSocketMessageReader(websocket) as reader:
						reader.wait_for_message(count=1)
						list(reader.get_messages())
						redis_key = f"{config.redis_key('session')}:{ip_address_to_redis_key(session.client_addr)}:{session.session_id}"
						assert await redis.exists(redis_key)
						await redis.delete(redis_key)
						await reader.async_wait_for_message(count=1, timeout=10)
						msg = next(reader.get_messages())
						assert msg["type"] == "general_error"
						assert msg["error"]["message"] == "Session expired or deleted"
						assert session.deleted
						# await asyncio.sleep(1)
						# message = ChannelSubscriptionRequestMessage(
						# sender=CONNECTION_USER_CHANNEL,
						# channel="service:messagebus",
						# channels=["session:11111111-1111-1111-1111-111111111111"],
						# operation="add",
						# )
						# websocket.send_bytes(message.to_msgpack())

	finally:
		await session_manager.stop()
