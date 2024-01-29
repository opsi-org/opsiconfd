# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.test_obj_audit_hardware_on_host
"""

import json
from pathlib import Path

import pytest

from tests.utils import ADMIN_PASS, ADMIN_USER, OpsiconfdTestClient, clean_mysql, clean_redis, test_client  # pylint: disable=unused-import


@pytest.mark.parametrize("method", ("auditHardwareOnHost_updateObjects", "auditHardwareOnHost_createObjects"))
def test_hwaudit(
	method: str,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	host_id1 = "test-backend-rpc-host-1.opsi.test"
	host_key1 = "5913c501a2854587dec4e60d57676892"
	host_id2 = "test-backend-rpc-host-2.opsi.test"
	host_key2 = "e692485913c587de0d57676501a285c4"

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	clients = [
		{"type": "OpsiClient", "id": host_id1, "opsiHostKey": host_key1},
		{"type": "OpsiClient", "id": host_id2, "opsiHostKey": host_key2},
	]

	# Create clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [clients]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	audit_hardware_on_hosts_by_ident = {}
	for host_id, host_key in ((host_id1, host_key1), (host_id2, host_key2)):
		test_client.reset_cookies()
		test_client.auth = (host_id, host_key)

		rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardwareOnHost_setObsolete", "params": [host_id]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res

		rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardwareOnHost_getObjects", "params": [[], {"hostId": host_id}]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		assert res["result"] == []

		hwaudit = Path("tests/data/hwaudit/hwaudit.json").read_text(encoding="utf-8")
		hwaudit = hwaudit.replace("{{host_id}}", host_id)
		audit_hardware_on_hosts = json.loads(hwaudit)
		audit_hardware_on_hosts_by_ident[host_id] = {a["ident"]: a for a in audit_hardware_on_hosts}

		rpc = {"jsonrpc": "2.0", "id": 1, "method": method, "params": [audit_hardware_on_hosts]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res

		rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardwareOnHost_getObjects", "params": [[], {"hostId": host_id}]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res

		by_ident = {a["ident"]: a for a in res["result"]}
		assert sorted(audit_hardware_on_hosts_by_ident[host_id]) == sorted(by_ident)

	test_client.reset_cookies()
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	for host_id in (host_id1, host_id2):
		rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardwareOnHost_getObjects", "params": [[], {"hostId": host_id}]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res

		by_ident = {a["ident"]: a for a in res["result"]}
		assert sorted(audit_hardware_on_hosts_by_ident[host_id]) == sorted(by_ident)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardwareOnHost_setObsolete", "params": [host_id1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "auditHardwareOnHost_getObjects", "params": [[], {"hostId": host_id2}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	by_ident = {a["ident"]: a for a in res["result"]}
	assert sorted(audit_hardware_on_hosts_by_ident[host_id2]) == sorted(by_ident)
