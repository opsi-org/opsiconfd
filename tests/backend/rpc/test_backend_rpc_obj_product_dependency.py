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

from .test_backend_rpc_obj_product import create_test_products
from .utils import cleanup_database  # pylint: disable=unused-import


def create_test_product_dependencies(test_client: OpsiconfdTestClient) -> tuple:  # pylint: disable=redefined-outer-name

	product1, product2 = create_test_products(test_client)

	product_dependency1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product2["id"],
		"requiredProductVersion": product2["productVersion"],
		"requiredPackageVersion": product2["packageVersion"],
	}
	product_dependency2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product1["id"],
		"requiredProductVersion": product1["productVersion"],
		"requiredPackageVersion": product1["packageVersion"],
	}

	# Create product 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_insertObject", "params": [product_dependency1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create product 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_insertObject", "params": [product_dependency2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return (product_dependency1, product_dependency2)


def check_products_dependencies(
	test_client: OpsiconfdTestClient, product_dependencies: list  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	for product_dependency in product_dependencies:
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "productDependency_getObjects",
			"params": [[], {"productId": product_dependency["productId"]}],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		print(res)
		dependency = res["result"][0]
		for attr, val in product_dependency.items():
			assert val == dependency[attr]


def test_product_dependency_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	# productDependency 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])


def test_product_dependency_createObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)

	product_dependency1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product2["id"],
		"requiredProductVersion": product2["productVersion"],
		"requiredPackageVersion": product2["packageVersion"],
	}
	product_dependency2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product1["id"],
		"requiredProductVersion": product1["productVersion"],
		"requiredPackageVersion": product1["packageVersion"],
	}

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_createObjects", "params": [[product_dependency1, product_dependency2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# productDependency 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])


def test_product_dependency_create(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)

	product3 = {
		"name": "test-backend-rpc-product-3",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": -100,
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

	product_dependency1 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product1["id"],
		"requiredProductVersion": product1["productVersion"],
		"requiredPackageVersion": product1["packageVersion"],
	}
	product_dependency2 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product3["id"],
		"requiredProductVersion": product3["productVersion"],
		"requiredPackageVersion": product3["packageVersion"],
	}

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_create", "params": list(product_dependency1.values())}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_create", "params": list(product_dependency2.values())}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# productDependency 1 should be created
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getObjects",
		"params": [[], {"productId": product_dependency1["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_dependency = res["result"][0]
	for attr, val in product_dependency1.items():
		assert val == product_dependency[attr]

	# productDependency 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])


def test_product_dependency_updateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	# product 1 should be created
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getObjects",
		"params": [[], {"productId": product_dependency1["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_dependency = res["result"][0]
	for attr, val in product_dependency1.items():
		assert val == product_dependency[attr]

	# Update product 1
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_updateObject",
		"params": [
			{
				"productId": product_dependency1["productId"],
				"productVersion": product_dependency1["productVersion"],
				"packageVersion": product_dependency1["packageVersion"],
				"productAction": product_dependency1["productAction"],
				"requiredProductId": product_dependency1["requiredProductId"],
				"requiredAction": "none",
			}
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"id": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_dependency = res["result"][0]
	for attr, val in product_dependency1.items():
		if attr == "requiredAction":
			assert product_dependency[attr] == "none"
		else:
			assert product_dependency[attr] == val

	# No new product should be created.
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_updateObject",
		"params": [
			{
				"productId": product_dependency1["productId"],
				"productVersion": product_dependency1["productVersion"],
				"packageVersion": product_dependency1["packageVersion"],
				"productAction": product_dependency1["productAction"],
				"requiredProductId": "new-product",
				"requiredAction": "none",
			}
		],
	}

	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"productId": "new-product"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0

	# update 2 products
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_updateObjects",
		"params": [
			[
				{
					"productId": product_dependency1["productId"],
					"productVersion": product_dependency1["productVersion"],
					"packageVersion": product_dependency1["packageVersion"],
					"productAction": product_dependency1["productAction"],
					"requiredProductId": product_dependency1["requiredProductId"],
					"requiredAction": "none",
				},
				{
					"productId": product_dependency2["productId"],
					"productVersion": product_dependency2["productVersion"],
					"packageVersion": product_dependency2["packageVersion"],
					"productAction": product_dependency2["productAction"],
					"requiredProductId": product_dependency2["requiredProductId"],
					"requiredAction": "none",
				},
			]
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getObjects",
		"params": [[], {"productId": product_dependency1["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	for product_dependency in res["result"]:
		for attr, val in product_dependency1.items():
			if attr == "requiredAction":
				assert product_dependency[attr] == "none"
			else:
				assert product_dependency[attr] == val


def test_product_dependency_getHashes(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getHashes",
		"params": [[], {"productId": product_dependency1["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in product_dependency1.items():
		assert val == poc[attr]

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getHashes",
		"params": [[], {"productId": product_dependency2["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in product_dependency2.items():
		assert val == poc[attr]


def test_product_dependency_getIdents(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getIdents", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		(
			f"{product_dependency1['productId']};"
			f"{product_dependency1['productVersion']};"
			f"{product_dependency1['packageVersion']};"
			f"{product_dependency1['productAction']};"
			f"{product_dependency1['requiredProductId']}"
		),
		(
			f"{product_dependency2['productId']};"
			f"{product_dependency2['productVersion']};"
			f"{product_dependency2['packageVersion']};"
			f"{product_dependency2['productAction']};"
			f"{product_dependency2['requiredProductId']}"
		),
	]


def test_product_dependency_delete(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 2

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_delete",
		"params": [
			product_dependency1["productId"],
			product_dependency1["productVersion"],
			product_dependency1["packageVersion"],
			product_dependency1["productAction"],
			product_dependency1["requiredProductId"],
		],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 1

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_delete",
		"params": [
			product_dependency2["productId"],
			product_dependency2["productVersion"],
			product_dependency2["packageVersion"],
			product_dependency2["productAction"],
			product_dependency2["requiredProductId"],
		],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0
