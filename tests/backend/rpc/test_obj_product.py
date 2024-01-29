# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product
"""
import pytest

from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	get_config,
	test_client,
)


def create_test_products(test_client: OpsiconfdTestClient) -> tuple:  # pylint: disable=redefined-outer-name
	product1 = {
		"name": "test-backend-rpc-product-1",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": 0,
		"description": "test-backend-rpc-product 1",
		"advice": "Some advice ",
		"id": "test-backend-rpc-product-1",
		"productVersion": "5.3.0",
		"packageVersion": "2",
		"type": "LocalbootProduct",
	}
	product2 = {
		"name": "test-backend-rpc-product-2",
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
	# Create product 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_insertObject", "params": [product1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create product 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_insertObject", "params": [product2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return (product1, product2)


def test_product_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product1, product2 = create_test_products(test_client)

	# product 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"name": product1["name"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product = res["result"][0]
	for attr, val in product1.items():
		assert val == product[attr]

	# product 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"name": product2["name"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product = res["result"][0]
	for attr, val in product2.items():
		assert val == product[attr]


def test_product_updateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)

	# product 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"name": product1["name"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product = res["result"][0]
	for attr, val in product1.items():
		assert val == product[attr]

	# Update product 1
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "product_updateObject",
		"params": [
			{
				"id": product1["id"],
				"productVersion": product1["productVersion"],
				"packageVersion": product1["packageVersion"],
				"type": product1["type"],
				"advice": "better advice",
			}
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"id": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product = res["result"][0]
	for attr, val in product1.items():
		if attr == "advice":
			assert "better advice" == product[attr]
		else:
			assert val == product[attr]

	# No new product should be created.
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "product_updateObject",
		"params": [
			{
				"id": "new-product",
				"name": "new-product",
				"productVersion": product1["productVersion"],
				"packageVersion": product1["packageVersion"],
				"type": product1["type"],
				"advice": "better advice",
			}
		],
	}

	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"id": "new-product"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0

	# update 2 products
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "product_updateObjects",
		"params": [
			[
				{
					"id": product1["id"],
					"name": product1["id"],
					"productVersion": product1["productVersion"],
					"packageVersion": product1["packageVersion"],
					"type": product1["type"],
					"advice": "best advice",
				},
				{
					"id": product2["id"],
					"name": product2["id"],
					"productVersion": product2["productVersion"],
					"packageVersion": product2["packageVersion"],
					"type": product2["type"],
					"advice": "best advice",
				},
			]
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"id": product1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	for product in res["result"]:
		for attr, val in product1.items():
			if attr == "advice":
				assert "best advice" == product[attr]
			else:
				assert val == product[attr]


def test_product_getIdents(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getIdents", "params": [[], {"id": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		f"{product1['id']};{product1['productVersion']};{product1['packageVersion']}",
		f"{product2['id']};{product2['productVersion']};{product2['packageVersion']}",
	]


def test_product_delete(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_delete", "params": [product1["id"]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"id": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 1

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_delete", "params": [product2["id"]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"id": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0


@pytest.mark.filterwarnings("ignore:.*calling deprecated method.*")
def test_product_get_hashes(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product1, product2 = create_test_products(test_client)

	# product 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getHashes", "params": [[], {"name": product1["name"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product = res["result"][0]
	for attr, val in product1.items():
		assert val == product[attr]

	# product 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getHashes", "params": [[], {"name": product2["name"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product = res["result"][0]
	for attr, val in product2.items():
		assert val == product[attr]
