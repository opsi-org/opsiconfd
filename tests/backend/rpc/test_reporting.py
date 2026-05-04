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
