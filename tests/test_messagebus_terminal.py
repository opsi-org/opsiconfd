# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.messagebus.terminal tests
"""

import uuid

import pytest
from opsicommon.messagebus.message import (
	ChannelSubscriptionEventMessage,
	TerminalCloseEventMessage,
	TerminalCloseRequestMessage,
	TerminalDataReadMessage,
	TerminalDataWriteMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
)

from opsiconfd.config import get_configserver_id
from opsiconfd.messagebus import get_user_id_for_user

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	WebSocketMessageReader,
	test_client,
)


@pytest.mark.parametrize(
	"channel",
	(
		"service:config:terminal",
		f"service:depot:{get_configserver_id()}:terminal",
	),
)
def test_messagebus_process(test_client: OpsiconfdTestClient, channel: str) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	user_id = get_user_id_for_user(ADMIN_USER)
	terminal_id = str(uuid.uuid4())
	with test_client:
		with test_client.websocket_connect("/messagebus/v1") as websocket:
			with WebSocketMessageReader(websocket, messagebus_messages=True) as reader:
				reader.wait_for_message(count=1)
				message = next(reader.get_messagbus_messages())
				assert isinstance(message, ChannelSubscriptionEventMessage)

				terminal_open_request = TerminalOpenRequestMessage(
					terminal_id=terminal_id, sender=user_id, channel=channel, shell="/bin/bash", cols=22, rows=11
				)
				websocket.send_bytes(terminal_open_request.to_msgpack())
				reader.wait_for_message(count=2)
				terminal_open_event = next(reader.get_messagbus_messages())
				assert isinstance(terminal_open_event, TerminalOpenEventMessage)
				assert terminal_open_event.terminal_id == terminal_id

				back_channel = terminal_open_event.back_channel
				assert back_channel == "service_worker:pytest:1:terminal"

				terminal_data_read = next(reader.get_messagbus_messages())
				assert isinstance(terminal_data_read, TerminalDataReadMessage)

				terminal_data_write = TerminalDataWriteMessage(
					sender=user_id, channel=back_channel, terminal_id=terminal_id, data=b"stty size\n"
				)
				websocket.send_bytes(terminal_data_write.to_msgpack())

				reader.wait_for_message(count=2)

				terminal_data_read = next(reader.get_messagbus_messages())
				assert isinstance(terminal_data_read, TerminalDataReadMessage)
				lines = terminal_data_read.data.decode("utf-8").split("\n")
				assert lines[0].strip() == "stty size"

				terminal_data_read = next(reader.get_messagbus_messages())
				assert isinstance(terminal_data_read, TerminalDataReadMessage)
				lines = terminal_data_read.data.decode("utf-8").split("\n")
				if lines[0].strip() != "11 22":
					reader.wait_for_message(count=1)
					terminal_data_read = next(reader.get_messagbus_messages())
					assert isinstance(terminal_data_read, TerminalDataReadMessage)
					lines = terminal_data_read.data.decode("utf-8").split("\n")
				assert lines[0].strip() == "11 22"

				terminal_close_request = TerminalCloseRequestMessage(sender=user_id, channel=back_channel, terminal_id=terminal_id)
				websocket.send_bytes(terminal_close_request.to_msgpack())

				reader.wait_for_message(count=1)
				terminal_close_event = next(reader.get_messagbus_messages())
				assert isinstance(terminal_close_event, TerminalCloseEventMessage)
				assert terminal_close_event.terminal_id == terminal_id
