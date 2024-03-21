# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test depotserver
"""
import subprocess
from contextlib import contextmanager
from pathlib import Path
from time import sleep
from types import EllipsisType
from typing import Generator
from unittest.mock import patch

import tomllib
from opsicommon import objects
from opsicommon.client.opsiservice import MessagebusListener, ServiceClient, ServiceVerificationFlags
from opsicommon.logging import get_logger
from opsicommon.messagebus import CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	ChannelSubscriptionEventMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
)

from opsiconfd.backend import get_unprotected_backend, reinit_backend
from opsiconfd.config import get_depotserver_id
from opsiconfd.setup import setup_depotserver
from opsiconfd.setup.backend import setup_backend
from opsiconfd.ssl import setup_ssl
from tests.utils import ADMIN_PASS, ADMIN_USER, Config, OpsiconfdTestClient, get_config, test_client  # noqa: F401

CONFIGSERVER = "opsiserver43-cs"

logger = get_logger()


@contextmanager
def depotserver_setup(tmp_path: Path) -> Generator[Config, None, None]:
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
			yield conf
		finally:
			opsi_config_file.write_bytes(orig_opsi_conf)
			reinit_backend()


def test_jsonrpc(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with depotserver_setup(tmp_path), test_client as client:
		backend = get_unprotected_backend()
		assert backend._server_role == "depotserver"
		idents = client.jsonrpc20(method="host_getIdents")["result"]
		assert idents == backend.host_getIdents()
		depot_id = get_depotserver_id()
		assert depot_id in idents
		assert CONFIGSERVER in [ident.split(".")[0] for ident in idents]


def test_messagebus_jsonrpc(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with depotserver_setup(tmp_path):
		depot_id = get_depotserver_id()
		service = ServiceClient(address=CONFIGSERVER, username=ADMIN_USER, password=ADMIN_PASS, verify=ServiceVerificationFlags.ACCEPT_ALL)

		class TestMessagebusListener(MessagebusListener):
			messages = []

			def message_received(self, message: Message) -> None:
				self.messages.append(message)

		logger.notice("Start application")
		with test_client:  # Start application
			sleep(5)
			logger.notice("Connect to configserver")
			listener = TestMessagebusListener(service.messagebus)
			with service.connection():
				service.messagebus.register_messagebus_listener(listener)
				service.connect_messagebus()
				# Wait for channel_subscription_event
				logger.notice("Wait for ChannelSubscriptionEventMessage")
				for _ in range(10):
					sleep(1)
					if len(listener.messages) == 1:
						break
				logger.notice("Got a message")
				assert len(listener.messages) == 1
				assert isinstance(listener.messages[0], ChannelSubscriptionEventMessage)
				listener.messages = []

				logger.notice("Sending JSONRPC request message")
				message = JSONRPCRequestMessage(
					sender=CONNECTION_USER_CHANNEL,
					channel=f"service:depot:{depot_id}:jsonrpc",
					method="depot_getDiskSpaceUsage",
					params=("/tmp",),
				)
				service.messagebus.send_message(message=message)
				logger.notice("Wait for JSONRPCResponseMessage")
				for _ in range(10):
					sleep(1)
					if len(listener.messages) == 1:
						break
				assert len(listener.messages) == 1
				assert isinstance(listener.messages[0], JSONRPCResponseMessage)
				assert listener.messages[0].result["capacity"] > 0


def test_setup_ssl(tmp_path: Path) -> None:  # noqa: F811
	cmds = []

	def execute(
		cmd: list[str], allow_exit_codes: list[int | EllipsisType] | tuple[int | EllipsisType] | None = None
	) -> subprocess.CompletedProcess:
		nonlocal cmds
		cmds.append(cmd)
		return subprocess.CompletedProcess(cmd, 0, b"", b"")

	with patch("opsicommon.ssl.linux.execute", execute), depotserver_setup(tmp_path) as conf:
		ssl_ca_cert = Path(conf.ssl_ca_cert)  # type: ignore[attr-defined]
		ssl_server_cert = Path(conf.ssl_server_cert)  # type: ignore[attr-defined]
		ssl_server_key = Path(conf.ssl_server_key)  # type: ignore[attr-defined]

		assert ssl_ca_cert.exists()
		assert ssl_server_cert.exists()
		assert ssl_server_key.exists()

		ssl_ca_cert.unlink()
		setup_ssl()
		assert len(cmds) == 1
		assert cmds[0] == ["update-ca-certificates"]
		assert ssl_ca_cert.exists()

		# Renew server certificate
		with get_config({"ssl_server_cert_renew_days": 10000}):
			crt_bytes = ssl_server_cert.read_bytes()
			key_bytes = ssl_server_key.read_bytes()
			assert setup_ssl()
			assert crt_bytes != ssl_server_cert.read_bytes()
			assert key_bytes != ssl_server_key.read_bytes()

		# No change
		assert not setup_ssl()


def test_rename_depotserver(tmp_path: Path) -> None:  # noqa: F811
	with depotserver_setup(tmp_path) as conf:
		opsi_config_file = Path(conf.opsi_config)
		depot_id = get_depotserver_id()
		new_depot_id = "new-depot-id.opsi.test"
		config1 = objects.UnicodeConfig(id="test1")
		config_state1 = objects.ConfigState(configId="test1", objectId=depot_id, values=["depotserver-value"])

		backend = get_unprotected_backend()
		host_ids = backend.host_getIdents()
		assert depot_id in host_ids
		assert new_depot_id not in host_ids

		backend.config_createObjects([config1])
		backend.configState_createObjects([config_state1])

		setup_backend(new_server_id=new_depot_id)

		opsi_conf = tomllib.loads(opsi_config_file.read_text(encoding="utf-8"))
		assert opsi_conf["host"]["id"] == new_depot_id

		backend = get_unprotected_backend()
		host_ids = backend.host_getIdents()
		assert depot_id not in host_ids
		assert new_depot_id in host_ids

		config_states = backend.configState_getObjects(objectId=new_depot_id, configId="test1")
		assert len(config_states) == 1
		assert config_states[0].objectId == new_depot_id
		assert config_states[0].values == ["depotserver-value"]
