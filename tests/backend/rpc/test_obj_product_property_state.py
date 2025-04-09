# -*- coding: utf-8 -*-

# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.obj_product_property_state
"""

import pytest
from opsicommon.objects import ConfigState, OpsiClient, OpsiDepotserver, ProductPropertyState

from opsiconfd.backend.auth import RPCACE
from opsiconfd.config import get_configserver_id
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	default_acl,
	get_config,
	test_client,
)

from .test_obj_product_property import create_test_product_properties


def create_test_clients(test_client: OpsiconfdTestClient) -> tuple[OpsiClient, OpsiClient]:  # noqa: F811
	client1 = OpsiClient(
		id="test-backend-rpc-host-1.opsi.test",
		opsiHostKey="11111111111111111111111111111111",
	)
	client2 = OpsiClient(
		id="test-backend-rpc-host-2.opsi.test",
		opsiHostKey="22222222222222222222222222222222",
	)
	res = test_client.jsonrpc20(method="host_createObjects", params=[[client1, client2]])
	assert "error" not in res
	return client1, client2


def create_test_product_property_states(test_client: OpsiconfdTestClient) -> list[ProductPropertyState]:  # noqa: F811
	product_property_bool, product_property_unicode = create_test_product_properties(test_client)

	client1, client2 = create_test_clients(test_client)

	product_property_states = [
		ProductPropertyState(
			productId=product_property_bool["productId"],
			propertyId=product_property_bool["propertyId"],
			objectId=client1.id,
			values=[False],
		),
		ProductPropertyState(
			productId=product_property_unicode["productId"],
			propertyId=product_property_unicode["propertyId"],
			objectId=client1.id,
			values=["123", "bla", "client1"],
		),
		ProductPropertyState(
			productId=product_property_bool["productId"],
			propertyId=product_property_bool["propertyId"],
			objectId=client2.id,
			values=[True],
		),
		ProductPropertyState(
			productId=product_property_unicode["productId"],
			propertyId=product_property_unicode["propertyId"],
			objectId=client2.id,
			values=["client2"],
		),
	]
	res = test_client.jsonrpc20(
		method="productPropertyState_createObjects",
		params=[product_property_states],
	)
	assert "error" not in res
	return product_property_states


def test_product_property_state_insertObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_states = create_test_product_property_states(test_client)

	product_property_states[1].values = ["new"]
	res = test_client.jsonrpc20(method="productPropertyState_insertObject", params=[product_property_states[1]])
	assert "error" not in res

	res = test_client.jsonrpc20(
		method="productPropertyState_getObjects",
		params=[
			[],
			{
				"productId": product_property_states[1].productId,
				"propertyId": product_property_states[1].propertyId,
				"objectId": product_property_states[1].objectId,
			},
		],
	)
	assert "error" not in res
	assert res["result"][0].values == ["new"]


def test_product_property_state_createObjects(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_states = create_test_product_property_states(test_client)
	res = test_client.jsonrpc20(method="productPropertyState_getObjects")
	assert "error" not in res
	assert len(res["result"]) == len(product_property_states)
	for product_property_state in product_property_states:
		assert product_property_state in res["result"]


def test_product_property_state_updateObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_states = create_test_product_property_states(test_client)

	assert product_property_states[0].values == [False]
	assert product_property_states[1].values == ["123", "bla", "client1"]
	assert product_property_states[2].values == [True]
	assert product_property_states[3].values == ["client2"]

	product_property_states[0].values = [True]
	product_property_states[1].values = ["client1_new"]
	product_property_states[2].values = [False]
	product_property_states[3].values = ["client2_new"]

	res = test_client.jsonrpc20(method="productPropertyState_updateObject", params=[product_property_states[0]])
	assert "error" not in res
	res = test_client.jsonrpc20(method="productPropertyState_updateObject", params=[product_property_states[1]])
	assert "error" not in res
	res = test_client.jsonrpc20(method="productPropertyState_updateObject", params=[product_property_states[2]])
	assert "error" not in res
	res = test_client.jsonrpc20(method="productPropertyState_updateObject", params=[product_property_states[3]])
	assert "error" not in res

	res = test_client.jsonrpc20(
		method="productPropertyState_getObjects",
		params=[
			[],
			{},
		],
	)
	assert "error" not in res
	assert len(res["result"]) == 4
	assert res["result"][0].values == [True]
	res["result"][0].values = [True]
	res["result"][1].values = ["client1_new"]
	res["result"][2].values = [False]
	res["result"][3].values = ["client2_new"]


@pytest.mark.filterwarnings("ignore:.*calling deprecated method.*")
def test_product_property_state_getHashes(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_states = create_test_product_property_states(test_client)

	res = test_client.jsonrpc20(method="productPropertyState_getHashes", params=[[], {"propertyId": product_property_states[0].propertyId}])

	assert "error" not in res
	poc = res["result"][0]
	for attr, val in product_property_states[0].to_hash().items():
		if attr != "type":
			assert val == getattr(poc, attr)


def test_product_property_state_getIdents(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_states = create_test_product_property_states(test_client)

	res = test_client.jsonrpc20(method="productPropertyState_getIdents", params=[[], {"productId": "test-backend-rpc-product*"}])
	assert "error" not in res

	assert sorted(res["result"]) == [
		(f"{product_property_states[0].productId};{product_property_states[0].propertyId};{product_property_states[0].objectId}"),
		(f"{product_property_states[2].productId};{product_property_states[2].propertyId};{product_property_states[2].objectId}"),
		(f"{product_property_states[1].productId};{product_property_states[1].propertyId};{product_property_states[1].objectId}"),
		(f"{product_property_states[3].productId};{product_property_states[3].propertyId};{product_property_states[3].objectId}"),
	]


def test_product_property_state_delete(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_property_states = create_test_product_property_states(test_client)

	res = test_client.jsonrpc20(method="productPropertyState_getObjects")
	assert "error" not in res
	assert len(res["result"]) == 4

	res = test_client.jsonrpc20(
		method="productPropertyState_delete",
		params={
			"productId": product_property_states[0].productId,
			"propertyId": product_property_states[0].propertyId,
			"objectId": product_property_states[0].objectId,
		},
	)
	assert "error" not in res

	res = test_client.jsonrpc20(method="productPropertyState_getObjects")
	assert len(res["result"]) == 3

	res = test_client.jsonrpc20(
		method="productPropertyState_delete",
		params={"productId": product_property_states[0].productId, "propertyId": product_property_states[0].propertyId, "objectId": None},
	)
	assert "error" not in res

	res = test_client.jsonrpc20(method="productPropertyState_getObjects")
	assert len(res["result"]) == 2

	res = test_client.jsonrpc20(
		method="productPropertyState_delete",
		params=[product_property_states[1].productId, product_property_states[1].propertyId, []],
	)
	assert "error" not in res

	res = test_client.jsonrpc20(method="productPropertyState_getObjects")
	assert len(res["result"]) == 0


def test_product_property_state_getValues(default_acl: dict[str, list[RPCACE]], test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	depot_id = "test-backend-rpc-depot.opsi.test"
	configserver_id = get_configserver_id()
	product_property_bool, product_property_unicode = create_test_product_properties(test_client)
	client1, client2 = create_test_clients(test_client)

	depot = OpsiDepotserver(id=depot_id, opsiHostKey="7dec5913c501a28545860d576768924f")
	res = test_client.jsonrpc20(method="host_createObjects", params=[[depot]])

	product_property_states = [
		ProductPropertyState(
			productId=product_property_bool["productId"],
			propertyId=product_property_bool["propertyId"],
			objectId=depot_id,
			values=[False],
		),
		ProductPropertyState(
			productId=product_property_unicode["productId"],
			propertyId=product_property_unicode["propertyId"],
			objectId=depot_id,
			values=["depot-default"],
		),
		ProductPropertyState(
			productId=product_property_bool["productId"],
			propertyId=product_property_bool["propertyId"],
			objectId=configserver_id,
			values=[True],
		),
		ProductPropertyState(
			productId=product_property_unicode["productId"],
			propertyId=product_property_unicode["propertyId"],
			objectId=configserver_id,
			values=["configserver-default"],
		),
	]
	res = test_client.jsonrpc20(
		method="productPropertyState_createObjects",
		params=[product_property_states],
	)
	assert "error" not in res

	# Assign client2 to depot
	client_to_depot = ConfigState(
		configId="clientconfig.depot.id",
		objectId=client2.id,
		values=[depot.id],
	)
	res = test_client.jsonrpc20(method="configState_insertObject", params=[client_to_depot])
	assert "error" not in res

	expected_defaults = {
		configserver_id: {
			product_property_bool["productId"]: {
				product_property_bool["propertyId"]: [
					True,
				],
			},
			product_property_unicode["productId"]: {
				product_property_unicode["propertyId"]: [
					"configserver-default",
				],
			},
		},
		depot_id: {
			product_property_bool["productId"]: {
				product_property_bool["propertyId"]: [
					False,
				],
			},
			product_property_unicode["productId"]: {
				product_property_unicode["propertyId"]: [
					"depot-default",
				],
			},
		},
	}

	# Get depot values
	res = test_client.jsonrpc20(
		method="productPropertyState_getValues", params={"object_ids": [depot_id, configserver_id], "with_defaults": False}
	)
	assert "error" not in res
	assert res["result"] == expected_defaults

	# Test again with client permissions
	for client in [client1, client2]:
		test_client.reset_cookies()
		test_client.auth = (client.id, client.opsiHostKey or "")
		res = test_client.jsonrpc20(
			method="productPropertyState_getValues", params={"object_ids": [depot_id, configserver_id], "with_defaults": False}
		)
		assert "error" not in res
		# No permission to access depot values
		assert res["result"] == {}

	test_client.reset_cookies()
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	# Client specific values not set, with_defaults=False, should return empty dict
	res = test_client.jsonrpc20(
		method="productPropertyState_getValues", params={"object_ids": [client1.id, client2.id], "with_defaults": False}
	)
	assert "error" not in res
	assert res["result"] == {}

	# Client specific values not set, with_defaults=True, should return values of assigned depot
	res = test_client.jsonrpc20(
		method="productPropertyState_getValues", params={"object_ids": [client1.id, client2.id], "with_defaults": True}
	)
	assert "error" not in res
	assert res["result"] == {
		client1.id: expected_defaults[configserver_id],
		client2.id: expected_defaults[depot_id],
	}

	# Test with empty filter
	res = test_client.jsonrpc20(method="productPropertyState_getValues", params={"with_defaults": True})
	assert "error" not in res
	assert res["result"] == {
		client1.id: expected_defaults[configserver_id],
		client2.id: expected_defaults[depot_id],
		depot_id: expected_defaults[depot_id],
		configserver_id: expected_defaults[configserver_id],
	}

	# Test product_ids and property_ids filter
	res = test_client.jsonrpc20(
		method="productPropertyState_getValues",
		params={
			"product_ids": product_property_unicode["productId"],
			"property_ids": [product_property_unicode["propertyId"]],
			"object_ids": [client1.id, client2.id, depot_id, configserver_id],
			"with_defaults": True,
		},
	)
	assert "error" not in res
	expected_filtered_defaults = {
		configserver_id: {product_property_unicode["productId"]: expected_defaults[configserver_id][product_property_unicode["productId"]]},
		depot_id: {product_property_unicode["productId"]: expected_defaults[depot_id][product_property_unicode["productId"]]},
	}
	assert res["result"] == {
		client1.id: expected_filtered_defaults[configserver_id],
		client2.id: expected_filtered_defaults[depot_id],
		depot_id: expected_filtered_defaults[depot_id],
		configserver_id: expected_filtered_defaults[configserver_id],
	}

	# Test again with client permissions
	for client in [client1, client2]:
		test_client.reset_cookies()
		test_client.auth = (client.id, client.opsiHostKey or "")
		res = test_client.jsonrpc20(
			method="productPropertyState_getValues",
			params={"object_ids": [depot_id, configserver_id, client1.id, client2.id], "with_defaults": True},
		)
		assert "error" not in res
		assert res["result"] == {client.id: expected_defaults[configserver_id] if client.id == client1.id else expected_defaults[depot_id]}

	test_client.reset_cookies()
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	# Create some client-specific product property states
	client_product_property_states = [
		ProductPropertyState(
			productId=product_property_bool["productId"],
			propertyId=product_property_bool["propertyId"],
			objectId=client1.id,
			values=[True],
		),
		ProductPropertyState(
			productId=product_property_unicode["productId"],
			propertyId=product_property_unicode["propertyId"],
			objectId=client2.id,
			values=["client2"],
		),
	]
	res = test_client.jsonrpc20(
		method="productPropertyState_createObjects",
		params=[client_product_property_states],
	)
	assert "error" not in res

	# Client specific values set, with_defaults=False, should return client-specific values only
	res = test_client.jsonrpc20(
		method="productPropertyState_getValues", params={"object_ids": [client1.id, client2.id], "with_defaults": False}
	)
	assert "error" not in res
	assert res["result"] == {
		client1.id: {product_property_bool["productId"]: {product_property_bool["propertyId"]: [True]}},
		client2.id: {product_property_unicode["productId"]: {product_property_unicode["propertyId"]: ["client2"]}},
	}

	# Client specific values set, with_defaults=True, should return client-specific values where set, otherwise depot values
	res = test_client.jsonrpc20(
		method="productPropertyState_getValues", params={"object_ids": [client1.id, client2.id], "with_defaults": True}
	)
	assert "error" not in res
	assert res["result"] == {
		client1.id: {
			product_property_bool["productId"]: {product_property_bool["propertyId"]: [True]},
			product_property_unicode["productId"]: {product_property_unicode["propertyId"]: ["configserver-default"]},
		},
		client2.id: {
			product_property_bool["productId"]: {product_property_bool["propertyId"]: [False]},
			product_property_unicode["productId"]: {product_property_unicode["propertyId"]: ["client2"]},
		},
	}

	# Test again with client permissions
	for client in [client1, client2]:
		test_client.reset_cookies()
		test_client.auth = (client.id, client.opsiHostKey or "")
		res = test_client.jsonrpc20(
			method="productPropertyState_getValues",
			params={"object_ids": [depot_id, configserver_id, client1.id, client2.id], "with_defaults": True},
		)
		assert "error" not in res
		if client.id == client1.id:
			assert res["result"] == {
				client1.id: {
					product_property_bool["productId"]: {product_property_bool["propertyId"]: [True]},
					product_property_unicode["productId"]: {product_property_unicode["propertyId"]: ["configserver-default"]},
				}
			}
		else:
			assert res["result"] == {
				client2.id: {
					product_property_bool["productId"]: {product_property_bool["propertyId"]: [False]},
					product_property_unicode["productId"]: {product_property_unicode["propertyId"]: ["client2"]},
				}
			}
