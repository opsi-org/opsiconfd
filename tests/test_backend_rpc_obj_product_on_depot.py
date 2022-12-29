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
	}
	pod2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productType": product2["type"],
		"depotId": FQDN,
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

	# product 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": pod1["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print("#####")
	print(pod1)
	print("#####")
	print(res)
	product = res["result"][0]
	for attr, val in pod1.items():
		assert val == product[attr]

	# product 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_getObjects", "params": [[], {"productId": pod2["productId"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product = res["result"][0]
	for attr, val in pod2.items():
		assert val == product[attr]
