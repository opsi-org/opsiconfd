# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd.backend.rpc.test_obj_audit_software
"""

from opsicommon.objects import AuditSoftware, AuditSoftwareOnClient, OpsiClient

from tests.utils import UnprotectedBackend, backend, clean_mysql, clean_redis  # noqa: F401


def test_audit_software(backend: UnprotectedBackend) -> None:  # noqa: F811
	client1 = OpsiClient(id="test-audit-software-1.opsi.test")
	client2 = OpsiClient(id="test-audit-software-2.opsi.test")
	audit_softwares = []
	audit_software_on_clients = []
	for num in range(1000):
		version = "1.2.3" if num % 2 else "1.2.4"
		name = f"package{num}"
		audit_softwares.append(
			AuditSoftware(
				name=name,
				version=version,
				subVersion="lin:",
				language="",
				architecture="",
				windowsSoftwareId=name,
				windowsDisplayName=name,
				windowsDisplayVersion=version,
			)
		)
		audit_software_on_clients.append(
			AuditSoftwareOnClient(
				name=name,
				version=version,
				subVersion="lin:",
				language="",
				architecture="",
				clientId=client1.id,
			)
		)
		audit_software_on_clients.append(
			AuditSoftwareOnClient(
				name=name,
				version=version,
				subVersion="lin:",
				language="",
				architecture="",
				clientId=client2.id,
			)
		)
	backend.host_createObjects([client1, client2])

	# Test AuditSoftware
	backend.auditSoftware_createObjects(audit_softwares)
	auditSoftwares = backend.auditSoftware_getObjects(version="1.2.3")
	for auditSoftware in auditSoftwares:
		assert isinstance(auditSoftware, AuditSoftware)
	assert len(auditSoftwares) == len(audit_softwares) / 2
	assert len(backend.auditSoftware_getObjects(name="package1", version="1.2.3")) == 1

	auditSoftwareIdents = backend.auditSoftware_getIdents(returnType="dict", version="1.2.3")
	assert len(auditSoftwareIdents) == len(audit_softwares) / 2
	for auditSoftwareIdent in auditSoftwareIdents:
		assert isinstance(auditSoftwareIdent, dict)
		assert auditSoftwareIdent["version"] == "1.2.3"

	backend.auditSoftware_delete(name="package1", version="1.2.3", subVersion=None, language=None, architecture=None)
	assert not backend.auditSoftware_getIdents(returnType="str", name="package1", version="1.2.3")

	auditSoftwares = backend.auditSoftware_getObjects(version="1.2.4")
	backend.auditSoftware_deleteObjects(auditSoftwares)
	auditSoftwares = backend.auditSoftware_getObjects()
	for auditSoftware in auditSoftwares:
		assert isinstance(auditSoftware, AuditSoftware)
		assert auditSoftware.version == "1.2.3"
		auditSoftware.installSize = 12345678

	backend.auditSoftware_updateObjects(auditSoftwares)
	auditSoftwares = backend.auditSoftware_getObjects()
	for auditSoftware in auditSoftwares:
		assert auditSoftware.version == "1.2.3"
		assert auditSoftware.installSize == 12345678

	backend.auditSoftware_createObjects(audit_softwares)
	assert len(backend.auditSoftware_getObjects()) == len(audit_softwares)

	# Test AuditSoftwareOnClient
	backend.auditSoftwareOnClient_createObjects(audit_software_on_clients)
	auditSoftwareOnClients = backend.auditSoftwareOnClient_getObjects(version="1.2.3")
	assert len(auditSoftwareOnClients) == len(audit_software_on_clients) / 2
	for auditSoftwareOnClient in auditSoftwareOnClients:
		assert isinstance(auditSoftwareOnClient, AuditSoftwareOnClient)

	assert len(backend.auditSoftwareOnClient_getObjects(version="1.2.4", name="package0")) == 2

	auditSoftwareOnClients = backend.auditSoftwareOnClient_getObjects(name="package0")
	assert len(auditSoftwareOnClients) == 2
	for auditSoftwareOnClient in auditSoftwareOnClients:
		assert auditSoftwareOnClient.name == "package0"
		auditSoftwareOnClient.usageFrequency = 123

	backend.auditSoftwareOnClient_updateObjects(auditSoftwareOnClients)

	auditSoftwareOnClients = backend.auditSoftwareOnClient_getObjects(name="package0")
	assert len(auditSoftwareOnClients) == 2
	for auditSoftwareOnClient in auditSoftwareOnClients:
		assert auditSoftwareOnClient.name == "package0"
		auditSoftwareOnClient.usageFrequency == 123

	backend.auditSoftwareOnClient_deleteObjects(auditSoftwareOnClients[0])
	assert len(backend.auditSoftwareOnClient_getObjects(name="package0")) == 1
	backend.auditSoftwareOnClient_updateObjects(auditSoftwareOnClients)
	auditSoftwareOnClients = backend.auditSoftwareOnClient_getObjects(name="package0")
	assert len(auditSoftwareOnClients) == 2

	backend.auditSoftwareOnClient_createObjects(audit_software_on_clients)

	backend.auditSoftwareOnClient_setObsolete(client1.id)
	assert len(backend.auditSoftwareOnClient_getObjects()) == len(audit_software_on_clients) / 2

	backend.auditSoftwareOnClient_setObsolete([client1.id, client2.id])
	assert len(backend.auditSoftwareOnClient_getObjects()) == 0

	backend.auditSoftwareOnClient_createObjects(audit_software_on_clients)
