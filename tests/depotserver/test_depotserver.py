# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test depotserver
"""
from pathlib import Path
from typing import Generator
from time import sleep
from _pytest.fixtures import FixtureFunction
from pytest import fixture

from opsicommon.logging import use_logging_config, LOG_TRACE
from opsicommon.client.opsiservice import ServiceClient, ServiceVerificationFlags, MessagebusListener
from opsicommon.messagebus import (
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	CONNECTION_USER_CHANNEL,
	Message,
	ChannelSubscriptionEventMessage,
)

from opsiconfd.backend import get_unprotected_backend, reinit_backend
from opsiconfd.config import get_depotserver_id
from opsiconfd.setup import setup_depotserver

from tests.utils import ADMIN_PASS, ADMIN_USER, OpsiconfdTestClient, get_config, test_client  # pylint: disable=unused-import

CONFIGSERVER = "opsiserver43-cs"


@fixture(autouse=False)
def depotserver_setup(tmp_path: Path) -> Generator[None, None, None]:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	with get_config({"ssl_ca_cert": str(ssl_ca_cert)}) as conf:
		opsi_config_file = Path(conf.opsi_config)
		orig_opsi_conf = opsi_config_file.read_bytes()
		depot_id = get_depotserver_id()
		unattended_configuration = {
			"configserver": CONFIGSERVER,
			"username": ADMIN_USER,
			"password": ADMIN_PASS,
			"depot_id": depot_id,
			"description": "pytest depotserver",
		}
		try:
			setup_depotserver(unattended_configuration)
			reinit_backend()
			yield
		finally:
			opsi_config_file.write_bytes(orig_opsi_conf)
			reinit_backend()


def test_jsonrpc(depotserver_setup: FixtureFunction, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client as client:
		backend = get_unprotected_backend()
		assert backend._server_role == "depotserver"  # pylint: disable=protected-access
		idents = client.jsonrpc20(method="host_getIdents")["result"]
		assert idents == backend.host_getIdents()
		depot_id = get_depotserver_id()
		assert depot_id in idents
		assert CONFIGSERVER in [ident.split(".")[0] for ident in idents]


def test_messagebus_jsonrpc(depotserver_setup: FixtureFunction, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	with use_logging_config(stderr_level=LOG_TRACE):
		depot_id = get_depotserver_id()
		service = ServiceClient(address=CONFIGSERVER, username=ADMIN_USER, password=ADMIN_PASS, verify=ServiceVerificationFlags.ACCEPT_ALL)

		class TestMessagebusListener(MessagebusListener):
			messages = []

			def message_received(self, message: Message) -> None:
				self.messages.append(message)

		with test_client:  # Start application
			sleep(5)
			listener = TestMessagebusListener(service.messagebus)
			with service.connection():
				service.messagebus.register_messagebus_listener(listener)
				service.connect_messagebus()
				message = JSONRPCRequestMessage(
					sender=CONNECTION_USER_CHANNEL,
					channel=f"service:depot:{depot_id}:jsonrpc",
					method="depot_getDiskSpaceUsage",
					params=("/tmp",),
				)
				service.messagebus.send_message(message=message)
				for _ in range(10):
					sleep(1)
					if len(listener.messages) == 2:
						break

				assert len(listener.messages) == 2
				assert isinstance(listener.messages[0], ChannelSubscriptionEventMessage)
				assert isinstance(listener.messages[1], JSONRPCResponseMessage)
				assert listener.messages[1].result["capacity"] > 0
