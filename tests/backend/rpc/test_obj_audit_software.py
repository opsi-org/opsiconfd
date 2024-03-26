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
	backend.auditSoftware_createObjects(audit_softwares)
	assert len(backend.auditSoftware_getObjects(version="1.2.3")) == len(audit_softwares) / 2
	assert len(backend.auditSoftware_getObjects(name="package1", version="1.2.3")) == 1
	backend.auditSoftwareOnClient_createObjects(audit_software_on_clients)
	assert len(backend.auditSoftwareOnClient_getObjects(version="1.2.3")) == len(audit_software_on_clients) / 2
	assert len(backend.auditSoftwareOnClient_getObjects(version="1.2.4", name="package0")) == 2
	assert len(backend.auditSoftwareOnClient_getObjects(name="package0")) == 2
	backend.auditSoftwareOnClient_setObsolete(client1.id)
	assert len(backend.auditSoftwareOnClient_getObjects()) == len(audit_software_on_clients) / 2
	backend.auditSoftwareOnClient_setObsolete([client1.id, client2.id])
	assert len(backend.auditSoftwareOnClient_getObjects()) == 0
	backend.auditSoftwareOnClient_createObjects(audit_software_on_clients)
