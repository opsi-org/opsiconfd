# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product
"""

from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Connection,
	OpsiconfdTestClient,
	clean_redis,
	database_connection,
	get_config,
	test_client,
)

from .test_backend_rpc_obj_product_on_depot import create_test_pods
from .utils import cleanup_database  # pylint: disable=unused-import


def create_test_pocs(test_client: OpsiconfdTestClient) -> tuple:  # pylint: disable=redefined-outer-name

	pod1, pod2 = create_test_pods(test_client)

	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	poc1 = {
		"productId": pod1["productId"],
		"productVersion": pod1["productVersion"],
		"packageVersion": pod1["packageVersion"],
		"productType": pod1["productType"],
		"clientId": client1["id"],
		"actionRequest": "none",
		"actionProgress": "none",
		"actionResult": "none",
		"installationStatus": "not_installed",
	}
	poc2 = {
		"productId": pod2["productId"],
		"productVersion": pod1["productVersion"],
		"packageVersion": pod1["packageVersion"],
		"productType": pod1["productType"],
		"clientId": client1["id"],
		"actionRequest": "none",
		"actionProgress": "none",
		"actionResult": "none",
		"installationStatus": "not_installed",
	}
	# Create poc 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_insertObject", "params": [poc1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create poc 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_insertObject", "params": [poc2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return (poc1, poc2)


def check_products_on_client(test_client: OpsiconfdTestClient, pocs: list) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	for product_on_client in pocs:
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "productOnClient_getObjects",
			"params": [[], {"productId": product_on_client["productId"]}],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		print(res)
		poc = res["result"][0]
		for attr, val in product_on_client.items():
			assert val == poc[attr]


def test_product_on_client_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	poc1, poc2 = create_test_pocs(test_client)

	check_products_on_client(test_client, [poc1, poc2])


def test_product_on_client_create_objects(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	pod1, pod2 = create_test_pods(test_client)

	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	poc1 = {
		"productId": pod1["productId"],
		"productVersion": pod1["productVersion"],
		"packageVersion": pod1["packageVersion"],
		"productType": pod1["productType"],
		"clientId": client1["id"],
		"actionRequest": "none",
		"actionProgress": "none",
		"actionResult": "none",
		"installationStatus": "not_installed",
	}
	poc2 = {
		"productId": pod2["productId"],
		"productVersion": pod2["productVersion"],
		"packageVersion": pod2["packageVersion"],
		"productType": pod2["productType"],
		"clientId": client1["id"],
		"actionRequest": "none",
		"actionProgress": "none",
		"actionResult": "none",
		"installationStatus": "not_installed",
	}
	# Create poc 1 and 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_createObjects", "params": [[poc1, poc2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	check_products_on_client(test_client, [poc1, poc2])


def test_product_on_client_create(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	pod1, pod2 = create_test_pods(test_client)

	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	poc1 = {
		"productId": pod1["productId"],
		"productType": pod1["productType"],
		"clientId": client1["id"],
		"installationStatus": "not_installed",
		"actionRequest": "none",
		"lastAction": "none",
		"actionProgress": "none",
		"actionResult": "none",
		"productVersion": pod1["productVersion"],
		"packageVersion": pod1["packageVersion"],
	}
	poc2 = {
		"productId": pod2["productId"],
		"productType": pod2["productType"],
		"clientId": client1["id"],
		"installationStatus": "not_installed",
		"actionRequest": "none",
		"lastAction": "none",
		"actionProgress": "none",
		"actionResult": "none",
		"productVersion": pod2["productVersion"],
		"packageVersion": pod2["packageVersion"],
	}
	# Create poc 1 and 2
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_create",
		"params": list(poc1.values()),
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_create",
		"params": list(poc2.values()),
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	check_products_on_client(test_client, [poc1, poc2])


def test_product_on_client_updateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	poc1, poc2 = create_test_pocs(test_client)

	# product on client 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getObjects", "params": [[], {"productId": poc1["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in poc1.items():
		assert val == poc[attr]

	# Update product on depot 1
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_updateObject",
		"params": [
			{
				"productId": poc1["productId"],
				"productVersion": poc1["productVersion"],
				"packageVersion": poc1["packageVersion"],
				"productType": poc1["productType"],
				"clientId": poc1["clientId"],
				"actionRequest": "setup",
			}
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in poc1.items():
		if attr == "actionRequest":
			assert poc[attr] == "setup"
		else:
			assert poc[attr] == val

	# No new product on client should be created.
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_updateObject",
		"params": [
			{
				"productId": "test-prod",
				"productVersion": poc1["productVersion"],
				"packageVersion": poc1["packageVersion"],
				"productType": poc1["productType"],
				"clientId": poc1["clientId"],
			}
		],
	}

	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getObjects", "params": [[], {"productId": "test-prod"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0

	# update 2 poc objects
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_updateObjects",
		"params": [
			[
				{
					"productId": poc1["productId"],
					"productVersion": poc1["productVersion"],
					"packageVersion": poc1["packageVersion"],
					"productType": poc1["productType"],
					"clientId": poc1["clientId"],
					"actionRequest": "uninstall",
				},
				{
					"productId": poc2["productId"],
					"productVersion": poc2["productVersion"],
					"packageVersion": poc2["packageVersion"],
					"productType": poc2["productType"],
					"clientId": poc2["clientId"],
					"actionRequest": "uninstall",
				},
			]
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getObjects", "params": [[], {"productId": poc1["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	for poc in res["result"]:
		for attr, val in poc1.items():
			if attr == "actionRequest":
				assert poc[attr] == "uninstall"
			else:
				assert poc[attr] == val


def test_product_on_client_getIdents(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	poc1, poc2 = create_test_pocs(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getIdents", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		f"{poc1['productId']};{poc1['productType']};{poc1['clientId']}",
		f"{poc2['productId']};{poc2['productType']};{poc2['clientId']}",
	]


def test_product_on_client_delete(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	poc1, poc2 = create_test_pocs(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getObjects", "params": [[], {}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 2

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_delete",
		"params": [poc1["productId"], poc1["productType"], poc1["clientId"]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 1

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_delete",
		"params": [poc2["productId"], poc1["productType"], poc2["clientId"]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0


def test_product_on_client_get_hashes(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	poc1, poc2 = create_test_pocs(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getHashes", "params": [[], {"productId": poc1["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in poc1.items():
		assert val == poc[attr]

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_getHashes", "params": [[], {"productId": poc2["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in poc2.items():
		assert val == poc[attr]


# TODO generateSequence
