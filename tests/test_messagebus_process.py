# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.process tests
"""

from opsicommon.messagebus.message import (
	ChannelSubscriptionEventMessage,
	ProcessDataReadMessage,
	ProcessDataWriteMessage,
	ProcessStartEventMessage,
	ProcessStartRequestMessage,
	ProcessStopEventMessage,
	ProcessStopRequestMessage,
)

from opsiconfd.messagebus import get_user_id_for_user

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	WebSocketMessageReader,
	test_client,
)


def test_messagebus_process(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	user_id = get_user_id_for_user(ADMIN_USER)
	with test_client:
		with test_client.websocket_connect("/messagebus/v1") as websocket:
			with WebSocketMessageReader(websocket, messagebus_messages=True) as reader:
				reader.wait_for_message(count=1)
				message = next(reader.get_messagbus_messages())
				assert isinstance(message, ChannelSubscriptionEventMessage)

				process_start_request = ProcessStartRequestMessage(sender=user_id, channel="service:config:process", command=("cat",))
				websocket.send_bytes(process_start_request.to_msgpack())
				reader.wait_for_message(count=1)
				process_start_event = next(reader.get_messagbus_messages())
				assert isinstance(process_start_event, ProcessStartEventMessage)

				channel = process_start_event.back_channel
				assert channel == "service_worker:pytest:1:process"

				process_data_write = ProcessDataWriteMessage(
					sender=user_id, channel=channel, process_id=process_start_event.process_id, stdin=b"Hello opsi\n"
				)
				websocket.send_bytes(process_data_write.to_msgpack())

				reader.wait_for_message(count=1)
				process_data_read = next(reader.get_messagbus_messages())
				assert isinstance(process_data_read, ProcessDataReadMessage)

				process_stop_request = ProcessStopRequestMessage(sender=user_id, channel=channel, process_id=process_start_event.process_id)
				websocket.send_bytes(process_stop_request.to_msgpack())

				reader.wait_for_message(count=1)
				process_stop_event = next(reader.get_messagbus_messages())
				assert isinstance(process_stop_event, ProcessStopEventMessage)
