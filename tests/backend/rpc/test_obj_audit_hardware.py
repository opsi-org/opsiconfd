# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.test_obj_audit_hardware
"""

import json
from collections import defaultdict
from pathlib import Path

from opsicommon.objects import AuditHardware, deserialize, serialize

from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	test_client,
)


def test_auditHardware_create_get_delete(  # pylint: disable=invalid-name,too-many-statements
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardware_getObjects", "params": []}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == []

	assert list(AuditHardware.hardware_attributes) == [
		"COMPUTER_SYSTEM",
		"CHASSIS",
		"BASE_BOARD",
		"BIOS",
		"SYSTEM_SLOT",
		"PORT_CONNECTOR",
		"PROCESSOR",
		"MEMORY_BANK",
		"MEMORY_MODULE",
		"CACHE_MEMORY",
		"PCI_DEVICE",
		"NETWORK_CONTROLLER",
		"AUDIO_CONTROLLER",
		"HDAUDIO_DEVICE",
		"IDE_CONTROLLER",
		"SCSI_CONTROLLER",
		"FLOPPY_CONTROLLER",
		"USB_CONTROLLER",
		"1394_CONTROLLER",
		"PCMCIA_CONTROLLER",
		"VIDEO_CONTROLLER",
		"FLOPPY_DRIVE",
		"TAPE_DRIVE",
		"HARDDISK_DRIVE",
		"DISK_PARTITION",
		"OPTICAL_DRIVE",
		"USB_DEVICE",
		"MONITOR",
		"KEYBOARD",
		"POINTING_DEVICE",
		"PRINTER",
		"TPM",
	]

	hwaudit = Path("tests/data/hwaudit/hwaudit.json").read_text(encoding="utf-8")
	hwaudit = hwaudit.replace("{{host_id}}", "")
	audit_hardware_on_hosts = json.loads(hwaudit)
	audit_hardwares = list({AuditHardware.fromHash(ahoh) for ahoh in audit_hardware_on_hosts})
	assert len(audit_hardwares) == 44

	by_hardware_class = defaultdict(list)
	for ahoh in audit_hardwares:
		by_hardware_class[ahoh.hardwareClass].append(ahoh)

	# Test createObjects with filter
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardware_createObjects", "params": [serialize(audit_hardwares)]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardware_getObjects", "params": []}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	ahs = deserialize(res["result"])
	assert sorted(ahs, key=lambda a: a.getIdent()) == sorted(audit_hardwares, key=lambda a: a.getIdent())  # type: ignore

	# Test getObjects with filter
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardware_getObjects", "params": [[], {"hardwareClass": "NETWORK_CONTROLLER"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	ahs = deserialize(res["result"])
	assert len(ahs) == 10
	assert sorted(ahs, key=lambda a: a.getIdent()) == sorted(
		by_hardware_class["NETWORK_CONTROLLER"],
		key=lambda a: a.getIdent(),  # type: ignore
	)

	# Test deleteObjects
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "auditHardware_deleteObjects",
		"params": [serialize(by_hardware_class["NETWORK_CONTROLLER"])],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardware_getObjects", "params": [[], {"hardwareClass": "NETWORK_CONTROLLER"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == []

	# Test deleteObjects one by one
	del_hws = by_hardware_class["IDE_CONTROLLER"]
	while del_hws:
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "auditHardware_deleteObjects",
			"params": [[serialize(del_hws.pop())]],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res

		rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardware_getObjects", "params": [[], {"hardwareClass": "IDE_CONTROLLER"}]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res

		ahs = deserialize(res["result"])
		assert len(ahs) == len(del_hws)
		assert sorted(ahs, key=lambda a: a.getIdent()) == sorted(del_hws, key=lambda a: a.getIdent())  # type: ignore

	# Test delete one by one
	del_hws = by_hardware_class["PCI_DEVICE"]
	while del_hws:
		ident = del_hws.pop().getIdent("dict")
		del ident["hardwareClass"]  # type: ignore
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "auditHardware_delete",
			"params": ["PCI_DEVICE", ident],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res

		rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardware_getObjects", "params": [[], {"hardwareClass": "PCI_DEVICE"}]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res

		ahs = deserialize(res["result"])
		assert len(ahs) == len(del_hws)
		assert sorted(ahs, key=lambda a: a.getIdent()) == sorted(del_hws, key=lambda a: a.getIdent())  # type: ignore
