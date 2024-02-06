# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend groups
"""


from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	test_client,
)


def test_group_insertObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	group1 = {
		"type": "HostGroup",
		"id": "test-backend-rpc-group-1",
		"description": "description",
	}
	group2 = {
		"type": "ProductGroup",
		"id": "test-backend-rpc-group-2",
		"description": "description",
	}
	# Create grtoup 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_insertObject", "params": [group1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create group 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_insertObject", "params": [group2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# group 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_getObjects", "params": [None, {"id": group1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	group = res["result"][0]
	for attr, val in group1.items():
		assert val == group[attr]

	# Update group 1 with null values
	group1["description"] = "new"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_insertObject", "params": [group1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# All values should be updated
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_getObjects", "params": [None, {"id": group1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	group = res["result"][0]
	for attr, val in group1.items():
		assert val == group[attr]


def test_group_updateObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	group1 = {
		"type": "HostGroup",
		"id": "test-backend-rpc-group-1",
		"description": "description",
	}
	group2 = {
		"type": "ProductGroup",
		"id": "test-backend-rpc-group-2",
		"description": "description",
	}

	# Call update
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_updateObject", "params": [group1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Should not be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_getObjects", "params": [None, {"id": group1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	group = res["result"] == []

	# Create group 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_insertObject", "params": [group1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create group 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_insertObject", "params": [group2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Update group 1
	group1["description"] = "new"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_updateObject", "params": [group1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Test update without type
	group1_upd = {
		"id": "test-backend-rpc-group-1",
		"description": "without type",
	}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_updateObject", "params": [group1_upd]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_getObjects", "params": [None, {"id": group1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	group = res["result"][0]
	assert group["description"] == group1_upd["description"]
	assert group["type"] == group1["type"]