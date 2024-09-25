# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
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
from opsicommon.client.opsiservice import (
	Messagebus,
	MessagebusListener,
	OpsiServiceConnectionError,
	ServiceClient,
	ServiceVerificationFlags,
	WebSocket,
)
from opsicommon.logging import get_logger, use_logging_config
from opsicommon.logging.constants import LOG_TRACE
from opsicommon.messagebus import CONNECTION_SESSION_CHANNEL, CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	ChannelSubscriptionEventMessage,
	ChannelSubscriptionRequestMessage,
	GeneralErrorMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	ProcessStartEventMessage,
	ProcessStartRequestMessage,
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

from opsiconfd.config import get_configserver_id
from opsiconfd.messagebus.websocket import _check_message_type_access
from opsiconfd.redis import Redis, async_redis_client, get_redis_connections, redis_client
from opsiconfd.session import OPSISession, session_manager
from opsiconfd.utils import compress_data, decompress_data

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	WebSocketMessageReader,
	clean_mysql,
	clean_redis,
	config,
	create_client_via_jsonrpc,
	get_config,
	opsiconfd_server,
	test_client,
)

logger = get_logger()


@pytest.mark.parametrize(
	"websocket_protocol, websocket_open_timeout, expect_timeout",
	[
		("websockets_opsiconfd", 2, True),
		("websockets_opsiconfd", 5, False),
		# Cannot set timeout for wsproto
		("wsproto_opsiconfd", 5, False),
	],
)
def test_websocket_open_timeout(websocket_protocol: str, websocket_open_timeout: int, expect_timeout: bool) -> None:  # noqa: F811
	with opsiconfd_server(
		{
			"websocket_protocol": websocket_protocol,
			"websocket_open_timeout": websocket_open_timeout,
			"development_options": ["delay-get-session"],  # Delays get_session for 3 seconds
		}
	) as server_conf:
		with ServiceClient(
			address=f"https://localhost:{server_conf.port}",
			username=ADMIN_USER,
			password=ADMIN_PASS,
			verify=ServiceVerificationFlags.ACCEPT_ALL,
			connect_timeout=5,
		) as client:
			if expect_timeout:
				with pytest.raises(OpsiServiceConnectionError):
					client.connect_messagebus()
			else:
				client.connect_messagebus()


@pytest.mark.parametrize("compression", ("", "lz4", "gzip"))
def test_messagebus_compression(test_client: OpsiconfdTestClient, compression: str) -> None:  # noqa: F811
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


def test_session_channel_subscription(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	connections = get_redis_connections()
	with test_client as client:
		with client.websocket_connect("/messagebus/v1") as websocket:
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

				sleep(1)
				message = Message(
					type="test", sender=CONNECTION_USER_CHANNEL, channel=session_channel, id="00000000-0000-4000-8000-000000000001"
				)
				websocket.send_bytes(message.to_msgpack())
				sleep(1)
				message = Message(
					type="test", sender=CONNECTION_USER_CHANNEL, channel=user_channel, id="00000000-0000-4000-8000-000000000002"
				)
				websocket.send_bytes(message.to_msgpack())

				reader.wait_for_message(count=2)
				messages = [Message.from_msgpack(msg) for msg in list(reader.get_raw_messages())]
				assert len(messages) == 2

				assert sorted([msg.id for msg in messages]) == [
					"00000000-0000-4000-8000-000000000001",
					"00000000-0000-4000-8000-000000000002",
				]

				# Subscribe for 2 new session channels
				other_channel1 = "session:11111111-1111-1111-1111-111111111111"
				other_channel2 = "session:22222222-2222-2222-2222-222222222222"

				message = ChannelSubscriptionRequestMessage(
					sender=CONNECTION_USER_CHANNEL, channel="service:messagebus", channels=[other_channel1, other_channel2], operation="add"
				)
				websocket.send_bytes(message.to_msgpack())

				start = time()
				reader.wait_for_message(count=1)
				diff = time() - start
				print(f"Channel subscription took {diff:0.3f} seconfds")
				assert diff < 1

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
				message = Message(
					type="test", sender=CONNECTION_USER_CHANNEL, channel=user_channel, id="00000000-0000-4000-8000-000000000004"
				)
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


def test_messagebus_multi_client_session_and_user_channel(
	config: Config,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
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

	with test_client as client:
		redis = redis_client()
		assert redis.hget(f"{config.redis_key('messagebus')}:channels:{channel}:info", "reader-count") is None

		with create_client_via_jsonrpc(client, "", host_id=host_id, host_key=host_key):
			client.auth = (host_id, host_key)
			with (
				client.websocket_connect("/messagebus/v1") as websocket1,
				client.websocket_connect("/messagebus/v1") as websocket2,
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


def test_messagebus_multi_client_service_channel(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client as client:
		with (
			client.websocket_connect("/messagebus/v1") as websocket1,
			client.websocket_connect("/messagebus/v1") as websocket2,
			client.websocket_connect("/messagebus/v1") as websocket3,
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
						sender=CONNECTION_USER_CHANNEL,
						channel="service:config:jsonrpc",
						rpc_id=str(rpc_id),
						method="accessControl_userIsAdmin",
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
			client.websocket_connect("/messagebus/v1") as websocket1,
			client.websocket_connect("/messagebus/v1") as websocket2,
			client.websocket_connect("/messagebus/v1") as websocket3,
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


def test_messagebus_jsonrpc(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	host_id = "msgbus-test-client.opsi.test"
	host_key = "92aa768a259dec1856013c4e458507d5"
	with test_client as client:
		with create_client_via_jsonrpc(client, "", host_id=host_id, host_key=host_key):
			client.auth = (host_id, host_key)
			with client.websocket_connect("/messagebus/v1") as websocket:
				with WebSocketMessageReader(websocket) as reader:
					reader.running.wait(3.0)
					sleep(2)
					reader.wait_for_message(count=1)
					assert next(reader.get_messages())["type"] == "channel_subscription_event"  # type: ignore[call-overload]
					jsonrpc_request_message1 = JSONRPCRequestMessage(
						sender=CONNECTION_USER_CHANNEL,
						channel="service:config:jsonrpc",
						rpc_id="1",
						method="accessControl_userIsAdmin",
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
						sender=CONNECTION_USER_CHANNEL,
						channel="service:config:jsonrpc",
						rpc_id="3",
						method="invalid",
						params=(1, 2, 3),
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


def test_messagebus_message_type_access(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	configserver_id = get_configserver_id()
	with test_client as client:
		with client.websocket_connect("/messagebus/v1") as websocket:
			with WebSocketMessageReader(websocket, print_raw_data=256) as reader:
				reader.wait_for_message(count=1)
				assert next(reader.get_messages())["type"] == "channel_subscription_event"  # type: ignore[call-overload]

				_check_message_type_access.cache_clear()
				with patch("opsiconfd.backend.unprotected_backend.available_modules", []):
					# Not checking against the actual value here, as we might use a license file for testing

					# Executing processes on depot must be allowed
					websocket.send_bytes(
						ProcessStartRequestMessage(
							sender=CONNECTION_USER_CHANNEL, channel=f"service:depot:{configserver_id}:process", command=("echo", "test")
						).to_msgpack()
					)
					reader.wait_for_message(count=5, timeout=3.0, error_on_timeout=False)
					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					assert isinstance(responses[0], ProcessStartEventMessage)

					# Executing processes on clients must be denied
					websocket.send_bytes(
						ProcessStartRequestMessage(
							sender=CONNECTION_USER_CHANNEL, channel="host:test-client.opsi.org", command=("echo", "test")
						).to_msgpack()
					)
					reader.wait_for_message(count=1, timeout=10.0)
					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					assert isinstance(responses[0], GeneralErrorMessage)
					assert responses[0].error.message == "Access to message type 'process_start_request' denied - check config and license"

				_check_message_type_access.cache_clear()
				with get_config({"disabled_features": ["messagebus_execute_process"]}):
					websocket.send_bytes(
						ProcessStartRequestMessage(
							sender=CONNECTION_USER_CHANNEL, channel=f"service:depot:{configserver_id}:process", command=("echo", "test")
						).to_msgpack()
					)
					reader.wait_for_message(count=5, timeout=3.0, error_on_timeout=False)

					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					print(responses[0])
					assert isinstance(responses[0], GeneralErrorMessage)
					assert responses[0].error.message == "Access to message type 'process_start_request' denied - check config and license"

				_check_message_type_access.cache_clear()
				with get_config({"disabled_features": ["messagebus_terminal"]}):
					websocket.send_bytes(
						TerminalOpenRequestMessage(
							sender=CONNECTION_USER_CHANNEL,
							channel=f"service:depot:{configserver_id}:terminal",
							terminal_id=str(uuid4()),
							rows=20,
							cols=150,
						).to_msgpack()
					)
					reader.wait_for_message(count=1, timeout=10.0)

					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					print(responses[0])
					assert isinstance(responses[0], GeneralErrorMessage)
					assert responses[0].error.message == "Access to message type 'terminal_open_request' denied - check config and license"

				_check_message_type_access.cache_clear()
				with get_config({"disabled_features": ["messagebus_execute_process_client"]}):
					# Executing processes on depot must be allowed
					websocket.send_bytes(
						ProcessStartRequestMessage(
							sender=CONNECTION_USER_CHANNEL, channel=f"service:depot:{configserver_id}:process", command=("echo", "test")
						).to_msgpack()
					)
					reader.wait_for_message(count=5, timeout=3.0, error_on_timeout=False)
					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					assert isinstance(responses[0], ProcessStartEventMessage)

					# Executing processes on clients must be denied
					websocket.send_bytes(
						ProcessStartRequestMessage(
							sender=CONNECTION_USER_CHANNEL, channel="host:test-client.opsi.org", command=("echo", "test")
						).to_msgpack()
					)
					reader.wait_for_message(count=1, timeout=10.0)
					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					assert isinstance(responses[0], GeneralErrorMessage)
					assert responses[0].error.message == "Access to message type 'process_start_request' denied - check config and license"

				_check_message_type_access.cache_clear()
				with get_config({"disabled_features": ["messagebus_terminal_client"]}):
					# Terminal on depot must be allowed
					websocket.send_bytes(
						TerminalOpenRequestMessage(
							sender=CONNECTION_USER_CHANNEL,
							channel=f"service:depot:{configserver_id}:terminal",
							terminal_id=str(uuid4()),
							rows=20,
							cols=150,
						).to_msgpack()
					)
					reader.wait_for_message(count=5, timeout=10.0, error_on_timeout=False)

					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					print(responses[0])
					assert isinstance(responses[0], TerminalOpenEventMessage)

					# Terminal on client must be denied
					websocket.send_bytes(
						TerminalOpenRequestMessage(
							sender=CONNECTION_USER_CHANNEL,
							channel="host:test-client.opsi.org",
							terminal_id=str(uuid4()),
							rows=20,
							cols=150,
						).to_msgpack()
					)
					reader.wait_for_message(count=1, timeout=10.0)

					responses = [Message.from_dict(msg) for msg in reader.get_messages()]  # type: ignore[arg-type,attr-defined]
					print(responses[0])
					assert isinstance(responses[0], GeneralErrorMessage)
					assert responses[0].error.message == "Access to message type 'terminal_open_request' denied - check config and license"

				_check_message_type_access.cache_clear()


def test_messagebus_terminal(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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

				reader.wait_for_message(count=2, timeout=5, error_on_timeout=False)
				data = b""
				for msg in reader.get_messages():
					message = Message.from_dict(msg)
					assert isinstance(message, TerminalDataReadMessage)
					assert message.terminal_id == terminal_id
					data += message.data
				assert "echo test\r\n" in data.decode("utf-8")

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


def test_trace(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with use_logging_config(stderr_level=LOG_TRACE):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		with test_client as client:
			logger.debug("Connecting to messagebus")
			with client.websocket_connect("/messagebus/v1") as websocket:
				with WebSocketMessageReader(websocket) as reader:
					logger.debug("Waiting for channel_subscription_event")
					reader.wait_for_message(count=1)
					msg = Message.from_dict(next(reader.get_messages()))
					assert isinstance(msg, ChannelSubscriptionEventMessage)
					logger.debug("Got channel_subscription_event")

					payload = randbytes(16 * 1024)
					message1 = TraceRequestMessage(
						sender=CONNECTION_USER_CHANNEL, channel=CONNECTION_SESSION_CHANNEL, payload=payload, trace={}
					)
					assert round(message1.created / 1000) == round(time())
					message1.trace["sender_ws_send"] = int(time() * 1000)
					logger.debug("Sending trace request to self")
					websocket.send_bytes(message1.to_msgpack())

					logger.debug("Waiting for trace request to self")
					reader.wait_for_message(count=1)
					message2 = Message.from_dict(next(reader.get_messages()))
					assert isinstance(message2, TraceRequestMessage)
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
					logger.debug("Sending trace response to self")
					websocket.send_bytes(message3.to_msgpack())

					logger.debug("Waiting for trace response to self")
					reader.wait_for_message(count=1)
					message4 = Message.from_dict(next(reader.get_messages()))
					assert isinstance(message4, TraceResponseMessage)

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


def test_messagebus_events(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with test_client as client:
		with client.websocket_connect("/messagebus/v1") as websocket:
			with WebSocketMessageReader(websocket, print_raw_data=256) as reader:
				message = ChannelSubscriptionRequestMessage(
					sender=CONNECTION_USER_CHANNEL,
					channel="service:messagebus",
					channels=["event:config_created", "event:host_connected", "event:host_disconnected"],
					operation="add",
				)
				websocket.send_bytes(message.to_msgpack())
				reader.wait_for_message(count=2)
				messages = list(reader.get_messages())
				assert messages[0]["type"] == "channel_subscription_event"
				assert messages[1]["type"] == "channel_subscription_event"

				host_id = "msgbus-test-client.opsi.test"
				host_key = "92aa768a259dec1856013c4e458507d5"
				with create_client_via_jsonrpc(client, "", host_id=host_id, host_key=host_key):
					client.reset_cookies()
					client.auth = (host_id, host_key)
					test_sess = client.websocket_connect("/messagebus/v1")
					# Do not use context manager here, because __exit__ will shut down the whole application
					test_sess.__enter__()
					sleep(1)
					test_sess.close()

				reader.wait_for_message(count=2)
				messages = list(reader.get_messages())

				assert messages[0]["type"] == "event"
				assert messages[0]["channel"] == "event:host_connected"
				assert messages[0]["event"] == "host_connected"
				assert messages[0]["data"]["host"]["id"] == "msgbus-test-client.opsi.test"

				assert messages[1]["type"] == "event"
				assert messages[1]["channel"] == "event:host_disconnected"
				assert messages[1]["event"] == "host_disconnected"
				assert messages[1]["data"]["host"]["id"] == "msgbus-test-client.opsi.test"

				client.auth = (ADMIN_USER, ADMIN_PASS)
				client.reset_cookies()
				conf = UnicodeConfig("test.config")
				result = client.jsonrpc20(method="config_createObjects", params=[conf.to_hash()])
				assert "error" not in result
				assert result["result"] is None

				reader.wait_for_message(count=1)
				msg = next(reader.get_messages())
				assert msg["type"] == "event"
				assert msg["channel"] == "event:config_created"
				assert msg["event"] == "config_created"
				assert msg["data"] == {"id": "test.config"}


async def test_messagebus_close_on_session_deleted(
	config: Config,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with (
		patch.object(session_manager, "_session_check_interval", 1),
		patch.object(session_manager, "_session_store_interval_min", 1),
		patch("opsiconfd.messagebus.websocket.MessagebusWebsocket._update_session_interval", 1.0),
	):
		with test_client as client:
			redis = await async_redis_client()
			with client.websocket_connect("/messagebus/v1") as websocket:
				session: OPSISession = websocket.scope["session"]
				with WebSocketMessageReader(websocket) as reader:
					reader.wait_for_message(count=1)
					list(reader.get_messages())
					redis_key = f"{config.redis_key('session')}:{session.session_id}"
					assert await redis.exists(redis_key)
					await redis.delete(redis_key)
					await reader.async_wait_for_message(count=1, timeout=10.0)
					msg = next(reader.get_messages())
					assert msg["type"] == "general_error"
					assert msg["error"]["message"] == "Session deleted"
					assert session.deleted


@pytest.mark.parametrize("websocket_protocol", ("websockets_opsiconfd", "wsproto_opsiconfd"))
def test_messagebus_ping(websocket_protocol: str) -> None:
	with opsiconfd_server(
		{"websocket_protocol": websocket_protocol, "websocket_ping_interval": 1, "websocket_ping_timeout": 3}
	) as server_conf:
		with ServiceClient(
			address=f"https://localhost:{server_conf.port}",
			username=ADMIN_USER,
			password=ADMIN_PASS,
			verify=ServiceVerificationFlags.ACCEPT_ALL,
		) as client:

			class ConFailMessagebusListener(MessagebusListener):
				connection_failed = 0
				connection_closed = 0

				def messagebus_connection_failed(self, messagebus: Messagebus, exception: Exception) -> None:
					print("messagebus_connection_failed:", exception)
					self.connection_failed += 1

				def messagebus_connection_closed(self, messagebus: Messagebus) -> None:
					print("messagebus_connection_closed")
					self.connection_closed += 1

			listener = ConFailMessagebusListener()

			ping_received = 0

			def on_ping(websocket: WebSocket, message: bytes) -> None:
				print("Ping received")
				nonlocal ping_received
				ping_received += 1

			client.messagebus._on_ping = on_ping  # type: ignore[method-assign]
			client.messagebus.register_messagebus_listener(listener)
			client.connect_messagebus()

			sleep(5)
			assert ping_received >= 3
			assert listener.connection_failed == 0
			assert listener.connection_closed == 0

			print("Block pong")
			# Block ServiceClient sending pongs, server should close websocket after ping timeout
			client.messagebus._app.sock.pong = lambda *args: None  # type: ignore
			sleep(5)

			assert listener.connection_closed > 0
