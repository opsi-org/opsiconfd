# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.reporting
"""

import asyncio
import json
from pathlib import Path

import pytest
from opsi.opsi.service.model.object import (
	AuditHardware,
	AuditSoftware,
	AuditSoftwareOnClient,
	ConfigState,
	OpsiClient,
	OpsiDepotserver,
	UnicodeConfig,
)

from opsiconfd.backend.rpc.main import UnprotectedBackend
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	backend,
	clean_mysql,
	clean_redis,
	default_acl,
	get_config,
	test_client,
)


def test_host_getClients(backend: UnprotectedBackend) -> None:  # noqa: F811
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)

	client1 = OpsiClient(id="test-host-getClients-client1.opsi.test")
	client2 = OpsiClient(id="test-host-getClients-client2.opsi.test")
	depot = OpsiDepotserver(id="test-host-getClients-depot.opsi.test")

	configs = [UnicodeConfig(id="clientconfig.depot.id")]

	backend.host_createObjects([client1, client2])
	backend.host_createObjects([depot])
	backend.config_createObjects(configs)

	clients = backend.reporting_getClients()
	assert len(clients) == 2

	audit_software = AuditSoftware(
		name="Debian 12",
		version="12.0",
		subVersion="lin:",
		language="en",
		architecture="x64",
		isOperatingSystem=True,
	)
	audit_software_on_client = AuditSoftwareOnClient(
		name="Debian 12",
		version="12.0",
		subVersion="lin:",
		language="en",
		architecture="x64",
		clientId=client1.id,
	)
	backend.auditSoftware_createObjects([audit_software])
	backend.auditSoftwareOnClient_createObjects([audit_software_on_client])

	hwaudit = Path("tests/data/hwaudit/hwaudit.json").read_text(encoding="utf-8")
	hwaudit = hwaudit.replace("{{host_id}}", client2.id)
	audit_hardware_on_hosts = json.loads(hwaudit)
	audit_hardwares = list({AuditHardware.fromHash(ahoh) for ahoh in audit_hardware_on_hosts})

	backend.auditHardware_createObjects(audit_hardwares)
	backend.auditHardwareOnHost_createObjects(audit_hardware_on_hosts)

	client_by_id = {client.id: client for client in backend.reporting_getClients()}
	assert client_by_id[client1.id].operating_system == "Debian 12"
	assert client_by_id[client1.id].operating_system_type == "linux"
	assert client_by_id[client1.id].device_vendor is None
	assert client_by_id[client1.id].device_model is None
	assert client_by_id[client1.id].device_ram is None
	assert client_by_id[client1.id].device_processor is None
	assert client_by_id[client1.id].device_sn is None

	assert client_by_id[client2.id].operating_system is None
	assert client_by_id[client2.id].operating_system_type is None
	assert client_by_id[client2.id].device_vendor == "QEMU"
	assert client_by_id[client2.id].device_model == "Standard PC (i440FX + PIIX, 1996)"
	assert round(client_by_id[client2.id].device_ram, 2) == 8191.48
	assert client_by_id[client2.id].device_processor is None
	assert client_by_id[client2.id].device_sn is None

	config_states = [ConfigState(configId="clientconfig.depot.id", objectId=client2.id, values=[depot.id])]
	backend.configState_createObjects(config_states)

	clients = backend.reporting_getClients(depots=[depot.id])
	assert len(clients) == 1


@pytest.mark.parametrize("method", ("reporting_getClients", "host_getClients"))
def test_get_clients_client_sees_only_own_hardware_and_software(
	method: str,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	host_id1 = "test-get-clients-1.opsi.test"
	host_key1 = "5913c501a2854587dec4e60d57676892"
	host_id2 = "test-get-clients-2.opsi.test"
	host_key2 = "e692485913c587de0d57676501a285c4"

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	clients = [
		{"type": "OpsiClient", "id": host_id1, "opsiHostKey": host_key1},
		{"type": "OpsiClient", "id": host_id2, "opsiHostKey": host_key2},
	]
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [clients]}
	assert "error" not in test_client.post("/rpc", json=rpc).json()

	hwaudit_template = Path("tests/data/hwaudit/hwaudit.json").read_text(encoding="utf-8")
	for host_id, host_key in ((host_id1, host_key1), (host_id2, host_key2)):
		test_client.reset_cookies()
		test_client.auth = (host_id, host_key)
		audit_hardware_on_hosts = json.loads(hwaudit_template.replace("{{host_id}}", host_id))
		rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardwareOnHost_updateObjects", "params": [audit_hardware_on_hosts]}
		assert "error" not in test_client.post("/rpc", json=rpc).json()
		software = {
			"type": "AuditSoftwareOnClient",
			"clientId": host_id,
			"name": "Debian 12",
			"version": "12.0",
			"subVersion": "lin:",
			"language": "en",
			"architecture": "x64",
		}
		rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditSoftwareOnClient_createObjects", "params": [[software]]}
		assert "error" not in test_client.post("/rpc", json=rpc).json()

	def get_clients() -> dict[str, dict]:
		rpc = {"jsonrpc": "2.0", "id": 1, "method": method, "params": []}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		return {c["id"]: c for c in res["result"]}

	# Admin sees all data
	test_client.reset_cookies()
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	by_id = get_clients()
	assert by_id[host_id1]["device_vendor"] == by_id[host_id2]["device_vendor"] is not None

	# Client 2 sees only its own data
	test_client.reset_cookies()
	test_client.auth = (host_id2, host_key2)
	by_id = get_clients()
	assert by_id[host_id2]["device_vendor"] is not None
	assert by_id[host_id1]["device_vendor"] is None
	assert by_id[host_id1]["device_model"] is None
	assert by_id[host_id1].get("operating_system") is None
	assert by_id[host_id1].get("device_sn") is None
