# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.test_obj_audit_hardware_on_host
"""

from pathlib import Path
import json

from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_redis,
	test_client,
	database_connection,
)

from .utils import cleanup_database  # pylint: disable=unused-import


def test_hwaudit(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	host_id = "test-backend-rpc-host-1.opsi.test"
	host_key = "5913c501a2854587dec4e60d57676892"

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client = {"type": "OpsiClient", "id": host_id, "opsiHostKey": host_key}
	# Create client
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	test_client.reset_cookies()
	test_client.auth = (host_id, host_key)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardwareOnHost_setObsolete", "params": [host_id]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 2, "method": "auditHardwareOnHost_getObjects", "params": [[], {"hostId": host_id}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == []

	hwaudit = Path("tests/data/hwaudit/hwaudit.json").read_text(encoding="utf-8")
	hwaudit = hwaudit.replace("{{host_id}}", host_id)
	audit_hardware_on_hosts = json.loads(hwaudit)
	audit_hardware_on_hosts_by_ident = {a["ident"]: a for a in audit_hardware_on_hosts}

	rpc = {"jsonrpc": "2.0", "id": 3, "method": "auditHardwareOnHost_createObjects", "params": [audit_hardware_on_hosts]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 4, "method": "auditHardwareOnHost_getObjects", "params": [[], {"hostId": host_id}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	by_ident = {a["ident"]: a for a in res["result"]}
	assert sorted(audit_hardware_on_hosts_by_ident) == sorted(by_ident)

	rpc = {"jsonrpc": "2.0", "id": 5, "method": "auditHardwareOnHost_setObsolete", "params": [host_id]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 6, "method": "auditHardwareOnHost_getObjects", "params": [[], {"hostId": host_id}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == []
