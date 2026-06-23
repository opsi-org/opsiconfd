# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.messagebus.terminal tests
"""

import uuid
from asyncio import sleep
from time import sleep as blocking_sleep
from unittest.mock import AsyncMock, patch

import pytest
from opsi.opsi.messagebus import (
	CONNECTION_USER_CHANNEL,
	ChannelSubscriptionEventMessage,
	TerminalCloseEventMessage,
	TerminalCloseRequestMessage,
	TerminalDataReadMessage,
	TerminalDataWriteMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
)
from opsi.opsi.service.model.object import AuditLogEventType
from starlette.websockets import WebSocketState

from opsiconfd.config import get_configserver_id
from opsiconfd.messagebus import get_user_id_for_user
from opsiconfd.messagebus.websocket import MessagebusWebsocket

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	UnprotectedBackend,
	WebSocketMessageReader,
	backend,
	test_client,
)


def _get_terminal_audit_logs(unprotected_backend: UnprotectedBackend, host_id: str, terminal_id: str) -> list:
	for _ in range(20):
		audit_logs = unprotected_backend.auditLog_getObjects(filter={"hostId": host_id}, orderBy={"created": "asc"})
		terminal_audit_logs = [audit_log for audit_log in audit_logs if audit_log.message and terminal_id in audit_log.message]
		if len(terminal_audit_logs) >= 2:
			return terminal_audit_logs
		blocking_sleep(0.1)
	return terminal_audit_logs


@pytest.mark.parametrize(
	"channel",
	(
		"service:config:terminal",
		f"service:depot:{get_configserver_id()}:terminal",
	),
)
def test_messagebus_process(test_client: OpsiconfdTestClient, backend: UnprotectedBackend, channel: str) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	user_id = get_user_id_for_user(ADMIN_USER)
	terminal_id = str(uuid.uuid4())
	with patch("opsiconfd.audit_log.audit_log_event_enabled", return_value=True), test_client:
		with test_client.websocket_connect("/messagebus/v1") as websocket:
			with WebSocketMessageReader(websocket, messagebus_messages=True, print_raw_data=256) as reader:
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

				reader.wait_for_message(count=10, timeout=6, error_on_timeout=False)

				data = b""
				messages = list(reader.get_messagbus_messages())
				for message in messages:
					assert isinstance(message, TerminalDataReadMessage)
					data += message.data

				lines = [line.strip() for line in data.decode("utf-8").split("\n")]
				assert "stty size" in lines
				assert "11 22" in lines

				terminal_close_request = TerminalCloseRequestMessage(sender=user_id, channel=back_channel, terminal_id=terminal_id)
				websocket.send_bytes(terminal_close_request.to_msgpack())

				reader.wait_for_message(count=1)
				terminal_close_event = next(reader.get_messagbus_messages())
				assert isinstance(terminal_close_event, TerminalCloseEventMessage)
				assert terminal_close_event.terminal_id == terminal_id

	server_id = get_configserver_id()
	terminal_audit_logs = _get_terminal_audit_logs(backend, server_id, terminal_id)
	assert [audit_log.eventType for audit_log in terminal_audit_logs] == [
		AuditLogEventType.SERVER_TERMINAL_OPEN,
		AuditLogEventType.SERVER_TERMINAL_CLOSE,
	]
	assert [audit_log.username for audit_log in terminal_audit_logs] == [ADMIN_USER, ADMIN_USER]
	assert [audit_log.actorType for audit_log in terminal_audit_logs] == ["user", "user"]


class TerminalAuditTestWebsocket:
	client_state = WebSocketState.CONNECTED
	application_state = WebSocketState.CONNECTED

	def __init__(self) -> None:
		self.sent_data: list[bytes] = []

	async def send_bytes(self, data: bytes) -> None:
		self.sent_data.append(data)


async def test_messagebus_terminal_client_audit_event_types() -> None:
	terminal_id = str(uuid.uuid4())
	client_id = "test-terminal-client.opsi.test"
	session = object()
	websocket = MessagebusWebsocket.__new__(MessagebusWebsocket)
	websocket.scope = {"session": session}
	websocket._compression = None
	websocket._terminal_id_to_host_type_and_id = {terminal_id: ("client", client_id)}
	test_websocket = TerminalAuditTestWebsocket()

	with patch("opsiconfd.messagebus.websocket.audit_terminal_event", new_callable=AsyncMock) as audit_terminal_event:
		await websocket._send_message_to_websocket(
			test_websocket,
			TerminalOpenEventMessage(
				sender=f"host:{client_id}",
				channel=CONNECTION_USER_CHANNEL,
				terminal_id=terminal_id,
				rows=24,
				cols=80,
			),
		)
		await sleep(0)
		await websocket._send_message_to_websocket(
			test_websocket,
			TerminalCloseEventMessage(
				sender=f"host:{client_id}",
				channel=CONNECTION_USER_CHANNEL,
				terminal_id=terminal_id,
			),
		)
		await sleep(0)

	assert [call.kwargs["event_type"] for call in audit_terminal_event.await_args_list] == [
		AuditLogEventType.CLIENT_TERMINAL_OPEN,
		AuditLogEventType.CLIENT_TERMINAL_CLOSE,
	]
	assert [call.kwargs["host_id"] for call in audit_terminal_event.await_args_list] == [client_id, client_id]
	assert audit_terminal_event.await_args_list[0].kwargs["session"] is session
	assert terminal_id not in websocket._terminal_id_to_host_type_and_id
	assert len(test_websocket.sent_data) == 2
