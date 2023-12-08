# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product_property_state
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

from .test_obj_product_property import create_test_product_properties
from .utils import cleanup_database  # pylint: disable=unused-import


def create_test_client(test_client: OpsiconfdTestClient) -> dict:  # pylint: disable=redefined-outer-name
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

	return client1


def create_test_product_property_states(test_client: OpsiconfdTestClient) -> tuple:  # pylint: disable=redefined-outer-name
	product_property1, product_property2 = create_test_product_properties(test_client)

	client1 = create_test_client(test_client)

	product_property_state1 = {
		"productId": product_property1["productId"],
		"propertyId": product_property1["propertyId"],
		"objectId": client1["id"],
		"values": [False],
	}
	product_property_state2 = {
		"productId": product_property2["productId"],
		"propertyId": product_property2["propertyId"],
		"objectId": client1["id"],
		"values": ["123", "bla", "test"],
	}

	# Create product property state 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productPropertyState_insertObject", "params": [product_property_state1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create product property state 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productPropertyState_insertObject", "params": [product_property_state2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return (product_property_state1, product_property_state2)


def check_products_property_states(
	test_client: OpsiconfdTestClient,
	product_property_states: list,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	for product_property_state in product_property_states:
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "productPropertyState_getObjects",
			"params": [[], {"productId": product_property_state["productId"]}],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		print(res)
		pproperty_state = res["result"][0]
		for attr, val in product_property_state.items():
			assert pproperty_state[attr] == val


def test_product_property_state_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_state1, product_property_state2 = create_test_product_property_states(test_client)

	check_products_property_states(test_client, [product_property_state1, product_property_state2])


def test_product_property_createObjects(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property1, product_property2 = create_test_product_properties(test_client)
	client1 = create_test_client(test_client)

	product_property_state1 = {
		"productId": product_property1["productId"],
		"propertyId": product_property1["propertyId"],
		"objectId": client1["id"],
		"values": [False],
	}
	product_property_state2 = {
		"productId": product_property2["productId"],
		"propertyId": product_property2["propertyId"],
		"objectId": client1["id"],
		"values": ["123", "bla", "test"],
	}

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_createObjects",
		"params": [[product_property_state1, product_property_state2]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	check_products_property_states(test_client, [product_property_state1, product_property_state2])


def test_product_property_state_updateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_state1, product_property_state2 = create_test_product_property_states(test_client)

	check_products_property_states(test_client, [product_property_state1, product_property_state2])

	# Update product property state 1
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_updateObject",
		"params": [
			{
				"productId": product_property_state1["productId"],
				"propertyId": product_property_state1["propertyId"],
				"objectId": product_property_state1["objectId"],
				"values": [True],
			}
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_getObjects",
		"params": [[], {"propertyId": product_property_state1["propertyId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_property = res["result"][0]
	for attr, val in product_property_state1.items():
		if attr == "values":
			assert product_property[attr] == [True]
		else:
			assert product_property[attr] == val

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_updateObjects",
		"params": [
			[
				{
					"productId": product_property_state1["productId"],
					"propertyId": product_property_state1["propertyId"],
					"objectId": product_property_state1["objectId"],
					"values": [False],
				},
				{
					"productId": product_property_state2["productId"],
					"propertyId": product_property_state2["propertyId"],
					"objectId": product_property_state2["objectId"],
					"values": ["test1", "test2"],
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
		"method": "productPropertyState_getObjects",
		"params": [[], {"propertyId": product_property_state2["propertyId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_dependency = res["result"][0]
	for attr, val in product_property_state2.items():
		if attr == "values":
			assert product_dependency[attr] == ["test1", "test2"]
		else:
			assert product_dependency[attr] == val


@pytest.mark.filterwarnings("ignore:.*calling deprecated method.*")
def test_product_property_state_getHashes(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_state1, product_property_state2 = create_test_product_property_states(test_client)

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_getHashes",
		"params": [[], {"propertyId": product_property_state1["propertyId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in product_property_state1.items():
		assert val == poc[attr]

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_getHashes",
		"params": [[], {"propertyId": product_property_state2["propertyId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in product_property_state2.items():
		assert val == poc[attr]


def test_product_property_state_getIdents(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_state1, product_property_state2 = create_test_product_property_states(test_client)

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_getIdents",
		"params": [[], {"productId": "test-backend-rpc-product*"}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		(f"{product_property_state1['productId']};" f"{product_property_state1['propertyId']};" f"{product_property_state1['objectId']}"),
		(f"{product_property_state2['productId']};" f"{product_property_state2['propertyId']};" f"{product_property_state2['objectId']}"),
	]


def test_product_property_state_delete(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_state1, product_property_state2 = create_test_product_property_states(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productPropertyState_getObjects", "params": [[], {}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 2

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_delete",
		"params": [product_property_state1["productId"], product_property_state1["propertyId"], product_property_state1["objectId"]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_getObjects",
		"params": [[], {}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 1

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_delete",
		"params": [product_property_state2["productId"], product_property_state2["propertyId"], product_property_state2["objectId"]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productPropertyState_getObjects",
		"params": [[], {}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0
