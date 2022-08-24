# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebustypes tests
"""

import time
from typing import Type, Union

import pytest

from opsiconfd.messagebus.types import (
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
	MessageTypes,
)


def test_message() -> None:
	with pytest.raises(TypeError, match="'type', 'sender', and 'channel'"):
		Message()  # type: ignore[call-arg] # pylint: disable=no-value-for-parameter
	msg = Message(type=MessageTypes.JSONRPC_REQUEST, sender="291b9f3e-e370-428d-be30-1248a906ae86", channel="service:config:jsonrpc")

	assert msg.type == "jsonrpc_request"
	assert abs(time.time() * 1000 - msg.created) <= 1
	assert msg.expires == 0
	assert msg.sender == "291b9f3e-e370-428d-be30-1248a906ae86"
	assert len(msg.id) == 36

	msg = Message(id="83932fac-3a6a-4a8e-aa70-4078ebfde8c1", type="custom_type", sender="291b9f3e-e370-428d-be30-1248a906ae86", channel="test")
	assert msg.type == "custom_type"
	assert msg.id == "83932fac-3a6a-4a8e-aa70-4078ebfde8c1"


def test_message_to_from_dict() -> None:
	msg1 = JSONRPCRequestMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
		sender="291b9f3e-e370-428d-be30-1248a906ae86",
		channel="service:config:jsonrpc",
		rpc_id="rpc1",
		method="test"
	)
	data = msg1.to_dict()
	assert isinstance(data, dict)
	msg2 = Message.from_dict(data)
	assert msg1 == msg2
	msg3 = Message.from_dict({
		"type": "jsonrpc_request",
		"sender": "*",
		"channel": "service:config:jsonrpc",
		"rpc_id": "1",
		"method": "noop"
	})
	assert isinstance(msg3, JSONRPCRequestMessage)


def test_message_to_from_msgpack() -> None:
	msg1 = JSONRPCResponseMessage(sender="291b9f3e-e370-428d-be30-1248a906ae86", channel="host:x.y.z", rpc_id="rpc1")  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
	data = msg1.to_msgpack()
	assert isinstance(data, bytes)
	msg2 = Message.from_msgpack(data)
	assert msg1 == msg2


def test_message_to_from_json() -> None:
	msg1 = Message(type="custom_message_type", sender="291b9f3e-e370-428d-be30-1248a906ae86", channel="xyz")
	data = msg1.to_json()
	assert isinstance(data, bytes)
	msg2 = Message.from_json(data)
	assert msg1 == msg2
	msg3 = Message.from_json(data.decode("utf-8"))
	assert msg1 == msg3


@pytest.mark.parametrize(
	"message_class, attributes, expected, exception",
	[
		(
			JSONRPCRequestMessage,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service:config:jsonrpc",
				"rpc_id": "1",
				"method": "noop",
				"params": ("1", "2")
			},
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service:config:jsonrpc",
				"rpc_id": "1",
				"method": "noop",
				"params": ("1", "2")
			},
			None,
		),
		(
			JSONRPCRequestMessage,
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service:config:jsonrpc",
				"rpc_id": "1",
				"method": "noop",
				"params": ("1", "2")
			},
			{
				"sender": "291b9f3e-e370-428d-be30-1248a906ae86",
				"channel": "service:config:jsonrpc",
				"rpc_id": "1",
				"method": "noop",
				"params": ("1", "2")
			},
			None,
		)
	],
)
def test_message_types(
	message_class: Type[Message],
	attributes: Union[dict, None],
	expected: Union[dict, None],
	exception: Union[Type[BaseException], None]
) -> None:
	attributes = attributes or {}
	expected = expected or {}
	if exception:
		with pytest.raises(exception):
			message_class(**attributes)
	else:
		values = message_class(**attributes).to_dict()
		for key, value in expected.items():
			assert values[key] == value
