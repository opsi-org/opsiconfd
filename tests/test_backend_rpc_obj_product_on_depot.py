# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product
"""

from typing import Generator

import pytest

from opsiconfd.config import FQDN

from .test_backend_rpc_obj_product import create_test_products
from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Connection,
	OpsiconfdTestClient,
	clean_redis,
	database_connection,
	get_config,
	test_client,
)


@pytest.fixture(autouse=True)
def cleanup_database(database_connection: Connection) -> Generator[None, None, None]:  # pylint: disable=redefined-outer-name
	cursor = database_connection.cursor()
	cursor.execute("DELETE FROM `PRODUCT_ON_DEPOT` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test-backend-rpc-product%'")
	database_connection.commit()
	yield
	cursor.execute("DELETE FROM `PRODUCT_ON_DEPOT` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test-backend-rpc-product%'")
	database_connection.commit()
	cursor.close()


def create_test_pods(test_client: OpsiconfdTestClient) -> tuple:  # pylint: disable=redefined-outer-name

	product1, product2 = create_test_products(test_client)

	pod1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"productType": product1["type"],
		"depotId": FQDN,
		"locked": False,
	}
	pod2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productType": product2["type"],
		"depotId": FQDN,
		"locked": False,
	}
	# Create pod 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_insertObject", "params": [pod1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create pod 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_insertObject", "params": [pod2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return (pod1, pod2)


def test_product_on_depot_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	pod1, pod2 = create_test_pods(test_client)

	# product on depot 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": pod1["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	pod = res["result"][0]
	for attr, val in pod1.items():
		assert val == pod[attr]

	# product on depot 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": pod2["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	pod = res["result"][0]
	for attr, val in pod2.items():
		assert val == pod[attr]


def test_product_on_depot_updateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	pod1, pod2 = create_test_pods(test_client)

	# product on depot 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": pod1["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	pod = res["result"][0]
	for attr, val in pod1.items():
		assert val == pod[attr]

	# Update product on depot 1
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnDepot_updateObject",
		"params": [
			{
				"productId": pod1["productId"],
				"productVersion": pod1["productVersion"],
				"packageVersion": pod1["packageVersion"],
				"productType": pod1["productType"],
				"depotId": pod1["depotId"],
				"locked": True,
			}
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	pod = res["result"][0]
	for attr, val in pod1.items():
		if attr == "locked":
			assert pod[attr]
		else:
			assert val == pod[attr]

	product3 = {
		"name": "test-backend-rpc-product-3",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": 0,
		"description": "test-backend-rpc-product 2",
		"advice": "Some advice ",
		"id": "test-backend-rpc-product-2",
		"productVersion": "5.3.0",
		"packageVersion": "2",
		"type": "LocalbootProduct",
	}
	# Create product 3
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_insertObject", "params": [product3]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# No new product on depot should be created.
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnDepot_updateObject",
		"params": [
			{
				"productId": product3["id"],
				"productVersion": product3["productVersion"],
				"packageVersion": product3["packageVersion"],
				"productType": product3["type"],
				"depotId": FQDN,
			}
		],
	}

	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": "test-backend-rpc-product-3"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0

	# update 2 products
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnDepot_updateObjects",
		"params": [
			[
				{
					"productId": pod1["productId"],
					"productVersion": pod1["productVersion"],
					"packageVersion": pod1["packageVersion"],
					"productType": pod1["productType"],
					"depotId": pod1["depotId"],
					"locked": True,
				},
				{
					"productId": pod2["productId"],
					"productVersion": pod2["productVersion"],
					"packageVersion": pod2["packageVersion"],
					"productType": pod2["productType"],
					"depotId": pod2["depotId"],
					"locked": True,
				},
			]
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": pod["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	for pod in res["result"]:
		for attr, val in pod1.items():
			if attr == "locked":
				assert pod[attr]
			else:
				assert val == pod[attr]


def test_product_on_depot_getIdents(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	pod1, pod2 = create_test_pods(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getIdents", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		f"{pod1['productId']};{pod1['productType']};{pod1['productVersion']};{pod1['packageVersion']};{pod1['depotId']}",
		f"{pod2['productId']};{pod2['productType']};{pod2['productVersion']};{pod2['packageVersion']};{pod2['depotId']}",
	]


def test_product_on_depot_delete(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	pod1, pod2 = create_test_pods(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_delete", "params": [pod1["productId"], pod1["depotId"]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 1

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_delete", "params": [pod2["productId"], pod2["depotId"]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0
