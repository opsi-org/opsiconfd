# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product
"""

from opsiconfd.config import get_depotserver_id
from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	get_config,
	test_client,
)

from .test_obj_product import create_test_products


def create_test_pods(test_client: OpsiconfdTestClient) -> tuple:  # pylint: disable=redefined-outer-name
	product1, product2 = create_test_products(test_client)
	depot_id = get_depotserver_id()
	pod1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"productType": product1["type"],
		"depotId": depot_id,
		"locked": False,
	}
	pod2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productType": product2["type"],
		"depotId": depot_id,
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


def check_products_on_depot(
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
	pods: list | tuple,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	for product_on_depot in pods:
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "productOnDepot_getObjects",
			"params": [[], {"productId": product_on_depot["productId"]}],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		print(res)
		poc = res["result"][0]
		for attr, val in product_on_depot.items():
			assert val == poc[attr]


def test_product_on_depot_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	check_products_on_depot(test_client, create_test_pods(test_client))


def test_product_on_depot_create(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product1, product2 = create_test_products(test_client)
	depot_id = get_depotserver_id()
	pod1 = {
		"productId": product1["id"],
		"productType": product1["type"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"depotId": depot_id,
		"locked": False,
	}
	pod2 = {
		"productId": product2["id"],
		"productType": product2["type"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"depotId": depot_id,
		"locked": False,
	}
	# Create pod 1 and 2
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnDepot_create",
		"params": list(pod1.values()),
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnDepot_create",
		"params": list(pod2.values()),
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	check_products_on_depot(test_client, [pod1, pod2])


def test_product_on_depot_updateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	depot_id = get_depotserver_id()
	pod1, pod2 = create_test_pods(test_client)

	check_products_on_depot(test_client, [pod1, pod2])

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
				"depotId": depot_id,
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

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnDepot_delete",
		"params": [pod1["productId"], pod1["depotId"], pod1["productType"], pod1["productVersion"], pod1["packageVersion"]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 1

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnDepot_delete",
		"params": [pod2["productId"], pod2["depotId"], pod2["productType"], pod2["productVersion"], pod2["packageVersion"]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0
