# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product_property
"""

import pytest

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

from .test_obj_product import create_test_products
from .utils import cleanup_database  # pylint: disable=unused-import


def create_test_product_properties(test_client: OpsiconfdTestClient) -> tuple:  # pylint: disable=redefined-outer-name
	product1, product2 = create_test_products(test_client)

	product_property1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"propertyId": "icon",
		"type": "BoolProductProperty",
		"description": "Some cool new properety #+,.!§$%&/()= test",
		"defaultValues": [True],
		"multiValue": False,
		"editable": False,
	}
	product_property2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"propertyId": "test-property",
		"type": "UnicodeProductProperty",
		"description": "Some cool new properety #+,.!§$%&/()= test",
		"defaultValues": ["value1", "value2"],
		"multiValue": True,
		"editable": True,
	}

	# Create product 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_insertObject", "params": [product_property1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create product 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_insertObject", "params": [product_property2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return (product_property1, product_property2)


def check_products_properties(  # pylint: disable=redefined-outer-name,unused-argument
	test_client: OpsiconfdTestClient,
	product_properties: list,
) -> None:
	for product_property in product_properties:
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "productProperty_getObjects",
			"params": [[], {"productId": product_property["productId"]}],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		print(res)
		pproperty = res["result"][0]
		for attr, val in product_property.items():
			assert val == pproperty[attr]


# TODO test change of default
def test_product_property_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property1, product_property2 = create_test_product_properties(test_client)

	check_products_properties(test_client, [product_property1, product_property2])


def test_product_property_createObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)

	product_property1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"propertyId": "icon",
		"type": "BoolProductProperty",
		"description": "Some cool new properety #+,.!§$%&/()= test",
		"defaultValues": [True],
		"multiValue": False,
		"editable": False,
	}
	product_property2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"propertyId": "test-property",
		"type": "UnicodeProductProperty",
		"description": "Some cool new properety #+,.!§$%&/()= test",
		"defaultValues": ["value1", "value2"],
		"multiValue": True,
		"editable": True,
	}

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_createObjects", "params": [[product_property1, product_property2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	check_products_properties(test_client, [product_property1, product_property2])


def test_product_property_create(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)

	product_property1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"propertyId": "icon",
		"type": "BoolProductProperty",
		"description": "Some cool new properety #+,.!§$%&/()= test",
		"possibleValues": [False, True],
		"defaultValues": [True],
		"multiValue": False,
		"editable": False,
	}
	product_property2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"propertyId": "test-property",
		"type": "UnicodeProductProperty",
		"description": "Some cool new properety #+,.!§$%&/()= test",
		"possibleValues": ["value1", "value2"],
		"defaultValues": ["value1", "value2"],
		"multiValue": True,
		"editable": True,
	}

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_create", "params": list(product_property1.values())}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_create", "params": list(product_property2.values())}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	check_products_properties(test_client, [product_property1, product_property2])


def test_product_property_updateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property1, product_property2 = create_test_product_properties(test_client)

	check_products_properties(test_client, [product_property1, product_property2])

	# Update product 1
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productProperty_updateObject",
		"params": [
			{
				"productId": product_property1["productId"],
				"productVersion": product_property1["productVersion"],
				"packageVersion": product_property1["packageVersion"],
				"propertyId": product_property1["propertyId"],
				"type": product_property1["type"],
				"description": "new description",
				"defaultValues": product_property1["defaultValues"],
				"multiValue": product_property1["multiValue"],
				"editable": product_property1["editable"],
			}
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productProperty_getObjects",
		"params": [[], {"propertyId": product_property1["propertyId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_property = res["result"][0]
	for attr, val in product_property1.items():
		if attr == "description":
			assert product_property[attr] == "new description"
		else:
			assert product_property[attr] == val

	# No new product should be created.
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productProperty_updateObject",
		"params": [
			{
				"productId": product_property1["productId"],
				"productVersion": product_property1["productVersion"],
				"packageVersion": product_property1["packageVersion"],
				"propertyId": "new-property",
				"type": product_property1["type"],
				"description": product_property1["description"],
				"defaultValues": False,
				"multiValue": product_property1["multiValue"],
				"editable": product_property1["editable"],
			}
		],
	}

	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_getObjects", "params": [[], {"propertyId": "new-property"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0

	# update 2 products
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productProperty_updateObjects",
		"params": [
			[
				{
					"productId": product_property1["productId"],
					"productVersion": product_property1["productVersion"],
					"packageVersion": product_property1["packageVersion"],
					"propertyId": product_property1["propertyId"],
					"type": product_property1["type"],
					"description": "better description",
					"defaultValues": product_property1["defaultValues"],
					"multiValue": product_property1["multiValue"],
					"editable": product_property1["editable"],
				},
				{
					"productId": product_property2["productId"],
					"productVersion": product_property2["productVersion"],
					"packageVersion": product_property2["packageVersion"],
					"propertyId": product_property2["propertyId"],
					"type": product_property2["type"],
					"description": "better description",
					"defaultValues": product_property2["defaultValues"],
					"multiValue": product_property2["multiValue"],
					"editable": product_property2["editable"],
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
		"method": "productProperty_getObjects",
		"params": [[], {"productId": product_property1["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	product_property = res["result"][0]
	for attr, val in product_property1.items():
		if attr == "description":
			assert product_property[attr] == "better description"
		else:
			assert product_property[attr] == val


@pytest.mark.filterwarnings("ignore:.*calling deprecated method.*")
def test_product_property_getHashes(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property1, product_property2 = create_test_product_properties(test_client)

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productProperty_getHashes",
		"params": [[], {"productId": product_property1["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in product_property1.items():
		assert val == poc[attr]

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productProperty_getHashes",
		"params": [[], {"productId": product_property2["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in product_property2.items():
		assert val == poc[attr]


def test_product_property_getIdents(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property1, product_property2 = create_test_product_properties(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_getIdents", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		(
			f"{product_property1['productId']};"
			f"{product_property1['productVersion']};"
			f"{product_property1['packageVersion']};"
			f"{product_property1['propertyId']}"
		),
		(
			f"{product_property2['productId']};"
			f"{product_property2['productVersion']};"
			f"{product_property2['packageVersion']};"
			f"{product_property2['propertyId']}"
		),
	]


def test_product_property_delete(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property1, product_property2 = create_test_product_properties(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_getObjects", "params": [[], {}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 2

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productProperty_delete",
		"params": [
			product_property1["productId"],
			product_property1["productVersion"],
			product_property1["packageVersion"],
			product_property1["propertyId"],
		],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 1

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productProperty_delete",
		"params": [
			product_property2["productId"],
			product_property2["productVersion"],
			product_property2["packageVersion"],
			product_property2["propertyId"],
		],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productProperty_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0
