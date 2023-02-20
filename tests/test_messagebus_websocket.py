# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus tests
"""

from random import randbytes
from time import sleep, time
from uuid import uuid4

import pytest
from opsicommon.messagebus import (  # type: ignore[import]
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionRequestMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageType,
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

from opsiconfd.utils import compress_data, decompress_data

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	WebSocketMessageReader,
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
					sender="@", channel="service:config:jsonrpc", rpc_id="1", method="accessControl_userIsAdmin"
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

			message = Message(type="test", sender="@", channel=session_channel, id="1")
			websocket.send_bytes(message.to_msgpack())
			message = Message(type="test", sender="@", channel=user_channel, id="2")
			websocket.send_bytes(message.to_msgpack())

			reader.wait_for_message(count=2)
			messages = [Message.from_msgpack(msg) for msg in list(reader.get_raw_messages())]
			assert len(messages) == 2

			assert sorted([msg.id for msg in messages]) == ["1", "2"]

			# Subscribe for 2 new session channels
			other_channel1 = "session:11111111-1111-1111-1111-111111111111"
			other_channel2 = "session:22222222-2222-2222-2222-222222222222"
			message = ChannelSubscriptionRequestMessage(
				sender="@", channel="service:messagebus", channels=[other_channel1, other_channel2], operation="add"
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

			message = Message(type="test", sender="@", channel=session_channel, id="3")
			websocket.send_bytes(message.to_msgpack())
			message = Message(type="test", sender="@", channel=user_channel, id="4")
			websocket.send_bytes(message.to_msgpack())
			message = Message(type="test", sender="@", channel=other_channel1, id="5")
			websocket.send_bytes(message.to_msgpack())
			message = Message(type="test", sender="@", channel=other_channel2, id="6")
			websocket.send_bytes(message.to_msgpack())

			reader.wait_for_message(count=4)
			messages = [Message.from_msgpack(msg) for msg in list(reader.get_raw_messages())]
			assert len(messages) == 4
			assert sorted([msg.id for msg in messages]) == ["3", "4", "5", "6"]


def test_messagebus_multi_client_session_and_user_channel(
	config: Config, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name
) -> None:
	host_id = "msgbus-test-client.opsi.test"
	host_key = "92aa768a259dec1856013c4e458507d5"
	with sync_redis_client() as redis:
		assert redis.hget(f"{config.redis_key('messagebus')}:channels:host:msgbus-test-client.opsi.test:info", "reader-count") is None

		with client_jsonrpc(test_client, "", host_id=host_id, host_key=host_key):
			test_client.auth = (host_id, host_key)
			with (
				test_client.websocket_connect("/messagebus/v1") as websocket1,
				test_client.websocket_connect("/messagebus/v1") as websocket2,
			):
				with (WebSocketMessageReader(websocket1) as reader1, WebSocketMessageReader(websocket2) as reader2):
					for reader, _websocket in ((reader1, websocket1), (reader2, websocket2)):
						reader.wait_for_message(count=1)
						messages = list(reader.get_messages())
						assert messages[0]["type"] == "channel_subscription_event"  # type: ignore[call-overload]
						assert len(messages[0]["subscribed_channels"]) == 2  # type: ignore[call-overload]
						assert "host:msgbus-test-client.opsi.test" in messages[0]["subscribed_channels"]  # type: ignore[call-overload]

					sleep(1)
					assert (
						redis.hget(f"{config.redis_key('messagebus')}:channels:host:msgbus-test-client.opsi.test:info", "reader-count")
						== b"2"
					)
					message = Message(type="test_multi_client", sender="@", channel="host:msgbus-test-client.opsi.test", id="1")
					websocket1.send_bytes(message.to_msgpack())
					for reader in (reader1, reader2):
						reader.wait_for_message(count=1)
						messages = list(reader.get_messages())
						# print(messages)
						assert len(messages) == 1
						assert messages[0]["type"] == "test_multi_client"
						assert messages[0]["id"] == "1"

					# print(list(reader2.get_messages()))
					with test_client.websocket_connect("/messagebus/v1") as websocket3:
						with WebSocketMessageReader(websocket3) as reader3:
							reader3.wait_for_message(count=1)
							messages = list(reader3.get_messages())
							assert messages[0]["type"] == "channel_subscription_event"
							assert len(messages[0]["subscribed_channels"]) == 2
							assert "host:msgbus-test-client.opsi.test" in messages[0]["subscribed_channels"]  # type: ignore[call-overload]

							sleep(1)
							assert (
								redis.hget(
									f"{config.redis_key('messagebus')}:channels:host:msgbus-test-client.opsi.test:info", "reader-count"
								)
								== b"3"
							)
							message = Message(type="test_multi_client", sender="@", channel="host:msgbus-test-client.opsi.test", id="2")
							websocket1.send_bytes(message.to_msgpack())
							for reader in (reader1, reader2, reader3):
								reader.wait_for_message(count=1)
								messages = list(reader.get_messages())
								assert len(messages) == 1
								assert messages[0]["type"] == "test_multi_client"  # type: ignore[call-overload]
								assert messages[0]["id"] == "2"  # type: ignore[call-overload]
					sleep(1)
					assert (
						redis.hget(f"{config.redis_key('messagebus')}:channels:host:msgbus-test-client.opsi.test:info", "reader-count")
						== b"2"
					)
			sleep(1)
			assert redis.hget(f"{config.redis_key('messagebus')}:channels:host:msgbus-test-client.opsi.test:info", "reader-count") == b"0"


def test_messagebus_multi_client_service_channel(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
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

				message = ChannelSubscriptionRequestMessage(
					sender="@", channel="service:messagebus", channels=["service:config:jsonrpc"], operation="add"
				)
				websocket.send_bytes(message.to_msgpack())

				reader.wait_for_message(count=1)
				messages = list(reader.get_messages())
				assert messages[0]["type"] == "channel_subscription_event"  # type: ignore[call-overload]
				assert len(messages[0]["subscribed_channels"]) == 3  # type: ignore[call-overload]

			count = 50
			for rpc_id in range(count):
				jsonrpc_request_message = JSONRPCRequestMessage(
					sender="@", channel="service:config:jsonrpc", rpc_id=str(rpc_id), method="accessControl_userIsAdmin"
				)
				websocket.send_bytes(jsonrpc_request_message.to_msgpack())

			sleep(5)
			all_messages = []
			for reader, websocket in ((reader1, websocket1), (reader2, websocket2), (reader3, websocket3)):
				reader.wait_for_message(count=1)
				messages = list(reader.get_messages())
				assert len(messages) > 0
				all_messages.extend(messages)

			assert len(all_messages) == count


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
						sender="@", channel="service:config:jsonrpc", rpc_id="1", method="accessControl_userIsAdmin"
					)
					websocket.send_bytes(jsonrpc_request_message1.to_msgpack())
					jsonrpc_request_message2 = JSONRPCRequestMessage(
						sender="@", channel="service:config:jsonrpc", rpc_id="2", method="config_create", params=("test", "descr")
					)
					websocket.send_bytes(jsonrpc_request_message2.to_msgpack())
					jsonrpc_request_message3 = JSONRPCRequestMessage(
						sender="@", channel="service:config:jsonrpc", rpc_id="3", method="invalid", params=(1, 2, 3)
					)
					websocket.send_bytes(jsonrpc_request_message3.to_msgpack())
					jsonrpc_request_message4 = JSONRPCRequestMessage(
						sender="@",
						channel="service:config:jsonrpc",
						rpc_id="4",
						method="hostControl_start",
						params=("client.opsi.test",),
					)
					websocket.send_bytes(jsonrpc_request_message4.to_msgpack())

					reader.wait_for_message(count=4, timeout=10.0)

					responses = sorted(
						[Message.from_dict(msg) for msg in reader.get_messages()],
						key=lambda m: getattr(m, "rpc_id", ""),  # type: ignore[arg-type,attr-defined]
					)
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
			with WebSocketMessageReader(websocket) as reader:
				reader.wait_for_message(count=1)
				message = Message.from_dict(next(reader.get_messages()))
				assert isinstance(message, ChannelSubscriptionEventMessage)

				terminal_id = str(uuid4())
				terminal_open_request = TerminalOpenRequestMessage(
					sender="@", channel="service:config:terminal", terminal_id=terminal_id, rows=20, cols=100
				)
				websocket.send_bytes(terminal_open_request.to_msgpack())

				reader.wait_for_message(count=2)

				responses = sorted(
					[Message.from_dict(msg) for msg in reader.get_messages()], key=lambda m: m.created  # type: ignore[arg-type,attr-defined]
				)

				assert isinstance(responses[0], TerminalOpenEventMessage)
				assert responses[0].rows
				assert responses[0].cols
				assert responses[0].terminal_id == terminal_id

				back_channel = responses[0].back_channel
				assert back_channel

				assert isinstance(responses[1], TerminalDataReadMessage)
				assert responses[1].terminal_id == terminal_id
				assert responses[1].data
				terminal_data_write = TerminalDataWriteMessage(
					sender="@", channel=back_channel, terminal_id=terminal_id, data=b"echo test\r"
				)
				websocket.send_bytes(terminal_data_write.to_msgpack())
				sleep(3)

				reader.wait_for_message(count=1)

				responses = sorted(
					[Message.from_dict(msg) for msg in reader.get_messages()], key=lambda m: m.created  # type: ignore[arg-type,attr-defined]
				)
				assert isinstance(responses[0], TerminalDataReadMessage)
				assert responses[0].terminal_id == terminal_id
				assert "echo test\r\n" in responses[0].data.decode("utf-8")
				terminal_resize_request = TerminalResizeRequestMessage(
					sender="@", channel=back_channel, terminal_id=terminal_id, rows=10, cols=20
				)
				websocket.send_bytes(terminal_resize_request.to_msgpack())

				reader.wait_for_message(count=1)
				responses = sorted(
					[Message.from_dict(msg) for msg in reader.get_messages()], key=lambda m: m.created  # type: ignore[arg-type,attr-defined]
				)
				assert responses[0].type == MessageType.TERMINAL_RESIZE_EVENT
				assert isinstance(responses[0], TerminalResizeEventMessage)
				assert responses[0].terminal_id == terminal_id
				assert responses[0].rows == 10
				assert responses[0].cols == 20


def test_trace(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with test_client.websocket_connect("/messagebus/v1") as websocket:
		with WebSocketMessageReader(websocket) as reader:
			reader.wait_for_message(count=1)
			next(reader.get_messages())

			payload = randbytes(16 * 1024)
			message1 = TraceRequestMessage(sender="@", channel="$", payload=payload, trace={})
			assert round(message1.created / 1000) == round(time())
			message1.trace["sender_ws_send"] = int(time() * 1000)
			websocket.send_bytes(message1.to_msgpack())

			reader.wait_for_message(count=1)
			message2 = TraceRequestMessage.from_dict(next(reader.get_messages()))
			message2.trace["recipient_ws_receive"] = timestamp()
			assert message2.created == message1.created

			message3 = TraceResponseMessage(
				sender="@",
				channel="$",
				ref_id=message2.id,
				req_trace=message2.trace,
				trace={"sender_ws_send": timestamp()},
				payload=message2.payload,
			)
			websocket.send_bytes(message3.to_msgpack())

			reader.wait_for_message(count=1)
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
