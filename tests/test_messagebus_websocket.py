# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus tests
"""

import pytest

from opsiconfd.messagebus.types import (
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
)
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
