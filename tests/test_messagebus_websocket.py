# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus tests
"""

from sqlite3 import OperationalError
from uuid import uuid4

import pytest
from opsicommon.messagebus import (  # type: ignore[import]
	ChannelSubscriptionRequestMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageType,
	TerminalDataWrite,
	TerminalOpenRequest,
	TerminalResizeRequest,
)

from opsiconfd.config import config
from opsiconfd.messagebus import get_messagebus_user_id_for_service_node
from opsiconfd.utils import compress_data, decompress_data

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	WebSocketMessageReader,
	clean_redis,
	client_jsonrpc,
	test_client,
	worker_main_loop,
)


@pytest.mark.parametrize("compression", ("", "lz4", "gzip"))
def test_messagebus_compression(test_client: OpsiconfdTestClient, compression: str) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client.websocket_connect(f"/messagebus/v1?compression={compression}") as websocket:
		with WebSocketMessageReader(websocket, decode=False) as reader:
			jsonrpc_request_message = JSONRPCRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender="*", channel="service:config:jsonrpc", rpc_id="1", method="accessControl_userIsAdmin"
			)
			data = jsonrpc_request_message.to_msgpack()
			if compression:
				data = compress_data(data, compression)
			websocket.send_bytes(data)

			reader.wait_for_message(timeout=5.0)
			raw_data = next(reader.get_messages())
			if compression:
				raw_data = decompress_data(raw_data, compression)  # type: ignore[arg-type]
			jsonrpc_response_message = Message.from_msgpack(raw_data)  # type: ignore[arg-type]
			assert isinstance(jsonrpc_response_message, JSONRPCResponseMessage)
			assert jsonrpc_response_message.rpc_id == jsonrpc_request_message.rpc_id
			assert jsonrpc_response_message.result is True
			assert jsonrpc_response_message.error is None


def test_messagebus_multi_client(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	host_id = "msgbus-test-client.opsi.test"
	host_key = "92aa768a259dec1856013c4e458507d5"
	with client_jsonrpc(test_client, "", host_id=host_id, host_key=host_key):
		test_client.auth = (host_id, host_key)
		with (test_client.websocket_connect("/messagebus/v1") as websocket1, test_client.websocket_connect("/messagebus/v1") as websocket2):
			with (WebSocketMessageReader(websocket1) as reader1, WebSocketMessageReader(websocket2) as reader2):
				for reader, websocket in ((reader1, websocket1), (reader2, websocket2)):
					message = ChannelSubscriptionRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
						sender="*", channel="service:messagebus", channels=["host:msgbus-test-client.opsi.test"], operation="add"
					)
					websocket.send_bytes(message.to_msgpack())
					reader.wait_for_message(count=1)
					messages = list(reader.get_messages())
					assert messages[0]["type"] == "channel_subscription_event"  # type: ignore[call-overload]
					assert len(messages[0]["subscribed_channels"]) == 2
					assert "host:msgbus-test-client.opsi.test" in messages[0]["subscribed_channels"]

				message = Message(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
					type="test_multi_client", sender="*", channel="host:msgbus-test-client.opsi.test", id="1"
				)
				websocket1.send_bytes(message.to_msgpack())
				for reader in (reader1, reader2):
					reader.wait_for_message(count=1)
					messages = list(reader.get_messages())
					# print(messages)
					assert len(messages) == 1
					assert messages[0]["type"] == "test_multi_client"  # type: ignore[call-overload]
					assert messages[0]["id"] == "1"  # type: ignore[call-overload]

				# print(list(reader2.get_messages()))
				with test_client.websocket_connect("/messagebus/v1") as websocket3:
					with WebSocketMessageReader(websocket3) as reader3:
						message = Message(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
							type="test_multi_client", sender="*", channel="host:msgbus-test-client.opsi.test", id="2"
						)
						websocket1.send_bytes(message.to_msgpack())
						for reader in (reader1, reader2, reader3):
							reader.wait_for_message(count=1)
							messages = list(reader.get_messages())
							assert len(messages) == 1
							assert messages[0]["type"] == "test_multi_client"  # type: ignore[call-overload]
							assert messages[0]["id"] == "2"  # type: ignore[call-overload]


def test_messagebus_jsonrpc(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	host_id = "msgbus-test-client.opsi.test"
	host_key = "92aa768a259dec1856013c4e458507d5"
	with client_jsonrpc(test_client, "", host_id=host_id, host_key=host_key):
		test_client.auth = (host_id, host_key)
		with test_client.websocket_connect("/messagebus/v1") as websocket:
			with WebSocketMessageReader(websocket) as reader:
				jsonrpc_request_message1 = JSONRPCRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
					sender="*", channel="service:config:jsonrpc", rpc_id="1", method="accessControl_userIsAdmin"
				)
				websocket.send_bytes(jsonrpc_request_message1.to_msgpack())
				jsonrpc_request_message2 = JSONRPCRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
					sender="*", channel="service:config:jsonrpc", rpc_id="2", method="config_create", params=("test", "descr")
				)
				websocket.send_bytes(jsonrpc_request_message2.to_msgpack())
				jsonrpc_request_message3 = JSONRPCRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
					sender="*", channel="service:config:jsonrpc", rpc_id="3", method="invalid", params=(1, 2, 3)
				)
				websocket.send_bytes(jsonrpc_request_message3.to_msgpack())

				reader.wait_for_message(count=3)

				responses = sorted(
					[Message.from_dict(msg) for msg in reader.get_messages()], key=lambda m: m.rpc_id  # type: ignore[arg-type,attr-defined]
				)

				assert isinstance(responses[0], JSONRPCResponseMessage)
				assert responses[0].rpc_id == jsonrpc_request_message1.rpc_id
				assert responses[0].result is False
				assert responses[0].error is None

				assert isinstance(responses[1], JSONRPCResponseMessage)
				assert responses[1].rpc_id == jsonrpc_request_message2.rpc_id
				assert responses[1].result == []
				assert responses[1].error is None

				assert isinstance(responses[2], JSONRPCResponseMessage)
				assert responses[2].rpc_id == jsonrpc_request_message3.rpc_id
				assert responses[2].result is None
				assert responses[2].error == {
					"code": 0,
					"message": "Invalid method 'invalid'",
					"data": {"class": "ValueError", "details": None},
				}


def xxx_test_messagebus_terminal(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	messagebus_node_id = get_messagebus_user_id_for_service_node(config.node_name)

	with test_client.websocket_connect("/messagebus/v1") as websocket:
		with WebSocketMessageReader(websocket) as reader:
			terminal_id = str(uuid4())
			message = TerminalOpenRequest(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender="*", channel=f"{messagebus_node_id}:terminal", terminal_id=terminal_id, rows=20, cols=100
			)
			websocket.send_bytes(message.to_msgpack())

			reader.wait_for_message(count=2)

			responses = sorted(
				[Message.from_dict(msg) for msg in reader.get_messages()], key=lambda m: m.created  # type: ignore[arg-type,attr-defined]
			)

			assert responses[0].type == MessageType.TERMINAL_OPEN_EVENT
			assert responses[0].rows
			assert responses[0].cols

			assert responses[0].terminal_id == terminal_id
			terminal_channel = responses[0].terminal_channel
			assert terminal_channel

			assert responses[1].type == MessageType.TERMINAL_DATA_READ
			assert responses[1].terminal_id == terminal_id
			assert responses[1].data

			message = TerminalDataWrite(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender="*", channel=terminal_channel, terminal_id=terminal_id, data="echo test\r"
			)
			websocket.send_bytes(message.to_msgpack())

			reader.wait_for_message(count=1)

			responses = sorted(
				[Message.from_dict(msg) for msg in reader.get_messages()], key=lambda m: m.created  # type: ignore[arg-type,attr-defined]
			)
			assert responses[0].type == MessageType.TERMINAL_DATA_READ
			assert responses[0].terminal_id == terminal_id
			assert "echo test\r\ntest\r\n" in responses[0].data.decode("utf-8")

			message = TerminalResizeRequest(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender="*", channel=terminal_channel, terminal_id=terminal_id, rows=10, cols=20
			)
			websocket.send_bytes(message.to_msgpack())

			reader.wait_for_message(count=1)
			responses = sorted(
				[Message.from_dict(msg) for msg in reader.get_messages()], key=lambda m: m.created  # type: ignore[arg-type,attr-defined]
			)
			assert responses[0].type == MessageType.TERMINAL_RESIZE_EVENT
			assert responses[0].terminal_id == terminal_id
			assert responses[0].rows == 10
			assert responses[0].cols == 20
