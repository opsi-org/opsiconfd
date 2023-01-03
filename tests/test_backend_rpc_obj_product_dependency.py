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
	cursor.execute("DELETE FROM `PRODUCT_DEPENDENCY` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test-backend-rpc-product%'")
	database_connection.commit()
	yield
	cursor.execute("DELETE FROM `PRODUCT_DEPENDENCY` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test-backend-rpc-product%'")
	database_connection.commit()
	cursor.close()


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


def test_product_dependency_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)
	print(product_dependency1)
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

	# product 1 should be created
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getObjects",
		"params": [[], {"productId": product_dependency2["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_dependency = res["result"][0]
	for attr, val in product_dependency2.items():
		assert val == product_dependency[attr]
