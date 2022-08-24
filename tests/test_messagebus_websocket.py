# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebroker tests
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
)


def inactive_test_messagebus_jsonrpc(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	host_id = "msgbus-test-client.opsi.test"
	host_key = "92aa768a259dec1856013c4e458507d5"
	with client_jsonrpc(test_client, "", host_id=host_id, host_key=host_key):
		test_client.auth = (host_id, host_key)
		with test_client.websocket_connect("/messagebus/v1") as websocket:
			with WebSocketMessageReader(websocket) as reader:
				jsonrpc_request_message = JSONRPCRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
					sender="*", channel="service:config:jsonrpc", rpc_id="1", method="accessControl_userIsAdmin"
				)
				websocket.send_bytes(jsonrpc_request_message.to_msgpack())
				reader.wait_for_message(timeout=5.0)
				msg_dict = next(reader.get_messages())
				jsonrpc_response_message = Message.from_dict(msg_dict)  # type: ignore[arg-type]
				assert isinstance(jsonrpc_response_message, JSONRPCResponseMessage)
				assert jsonrpc_response_message.rpc_id == jsonrpc_request_message.rpc_id
				assert jsonrpc_response_message.result is False
				assert jsonrpc_response_message.error is None


@pytest.mark.parametrize("compression", ("lz4", "gzip"))
def inactive_test_messagebus_compression(test_client: OpsiconfdTestClient, compression: str) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client.websocket_connect(f"/messagebus/v1?compression={compression}") as websocket:
		with WebSocketMessageReader(websocket, decode=False) as reader:
			jsonrpc_request_message = JSONRPCRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
				sender="*", channel="service:config:jsonrpc", rpc_id="1", method="accessControl_userIsAdmin"
			)
			websocket.send_bytes(compress_data(jsonrpc_request_message.to_msgpack(), compression))
			reader.wait_for_message(timeout=5.0)
			raw_data = next(reader.get_messages())
			jsonrpc_response_message = Message.from_msgpack(decompress_data(raw_data, compression))  # type: ignore[arg-type]
			assert isinstance(jsonrpc_response_message, JSONRPCResponseMessage)
			assert jsonrpc_response_message.rpc_id == jsonrpc_request_message.rpc_id
			# assert jsonrpc_response_message.result is True
			assert jsonrpc_response_message.error is None
