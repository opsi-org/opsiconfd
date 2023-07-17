# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product
"""

from pprint import pprint

import pytest
from opsicommon.objects import (
	ConfigState,
	LocalbootProduct,
	OpsiClient,
	OpsiDepotserver,
	ProductDependency,
	ProductOnClient,
	ProductOnDepot,
)

from opsiconfd.config import get_depotserver_id
from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Connection,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	database_connection,
	get_config,
	test_client,
)

from .test_obj_product_on_depot import create_test_pods
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
		"params": [poc1["productId"], poc1["clientId"], poc1["productType"]],
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
		"params": [poc2["productId"], poc2["clientId"], poc1["productType"]],
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


def _prepare_product_on_client_sequence_dependencies(  # pylint: disable=too-many-statements,too-many-locals,too-many-arguments
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name
	poc_status: list[tuple[str, str, str]],
	# productAction, requiredAction, requiredInstallationStatus, requirementType
	requirement: tuple[str | None, str | None, str | None, str | None],
) -> list[ProductOnClient]:
	depot1 = OpsiDepotserver(id="test-backend-rpc-depot-1.opsi.test")
	client1 = OpsiClient(id="test-backend-rpc-host-1.opsi.test")
	product1 = LocalbootProduct(id="test-backend-rpc-product1", productVersion="1", packageVersion="1", priority=100)
	product2 = LocalbootProduct(id="test-backend-rpc-product2", productVersion="1", packageVersion="1", priority=0)
	product3 = LocalbootProduct(id="test-backend-rpc-product3", productVersion="1", packageVersion="1", priority=-100)
	product_dependency = None
	if requirement[0]:
		product_dependency = ProductDependency(
			productId=product2.id,
			productVersion=product2.productVersion,
			packageVersion=product2.packageVersion,
			productAction=requirement[0],
			requiredProductId=product3.id,
			requiredProductVersion=product3.productVersion,
			requiredPackageVersion=product3.packageVersion,
			requiredAction=requirement[1],
			requiredInstallationStatus=requirement[2],
			requirementType=requirement[3],
		)
	product_on_depot1 = ProductOnDepot(
		productId=product1.id,
		productType=product1.getType(),
		productVersion=product1.productVersion,
		packageVersion=product1.packageVersion,
		depotId=depot1.id,
	)
	product_on_depot2 = ProductOnDepot(
		productId=product2.id,
		productType=product2.getType(),
		productVersion=product2.productVersion,
		packageVersion=product2.packageVersion,
		depotId=depot1.id,
	)
	product_on_depot3 = ProductOnDepot(
		productId=product3.id,
		productType=product3.getType(),
		productVersion=product3.productVersion,
		packageVersion=product3.packageVersion,
		depotId=depot1.id,
	)
	config_state = ConfigState(configId="clientconfig.depot.id", objectId=client1.id, values=[depot1.id])

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[depot1.to_hash(), client1.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "product_createObjects",
		"params": [[product1.to_hash(), product2.to_hash(), product3.to_hash()]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	if product_dependency:
		rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_createObjects", "params": [[product_dependency.to_hash()]]}
		res = test_client.post("/rpc", json=rpc).json()

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnDepot_createObjects",
		"params": [[product_on_depot1.to_hash(), product_on_depot2.to_hash(), product_on_depot3.to_hash()]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_createObjects", "params": [[config_state.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	product_on_clients = [
		ProductOnClient(
			productId=f"test-backend-rpc-{poc[0]}",
			productType="LocalbootProduct",
			clientId=client1.id,
			installationStatus=poc[1],
			actionRequest=poc[2],
		)
		for poc in poc_status
	]
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_createObjects",
		"params": [[poc.to_hash() for poc in product_on_clients]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return product_on_clients


# priorities: product1=100, product2=0, product3=-100
# product2 depends on product3
@pytest.mark.parametrize(
	"poc_status, requirement, expected_actions",
	(
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "not_installed", "setup")],
			# productAction, requiredAction, requiredInstallationStatus, requirementType
			(None, None, None, None),
			# No product dependencies, order must be based on priority only
			[("product1", "setup"), ("product2", "setup"), ("product3", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "not_installed", "none")],
			# productAction "setup" requires installationStatus "installed" before
			("setup", None, "installed", "before"),
			[("product1", "setup"), ("product3", "setup"), ("product2", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup")],
			# productAction "setup" requires installationStatus "installed" before
			("setup", None, "installed", "before"),
			[("product1", "setup"), ("product3", "setup"), ("product2", "setup")],
		),
		(
			[("product2", "not_installed", "setup")],
			# productAction "setup" requires installationStatus "installed" before
			("setup", None, "installed", "before"),
			[("product3", "setup"), ("product2", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "installed", "none")],
			# productAction "setup" requires installationStatus "installed" before (fulfilled)
			("setup", None, "installed", "before"),
			[("product1", "setup"), ("product2", "setup"), ("product3", "none")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "not_installed", "none")],
			# productAction "setup" requires installationStatus "installed"
			# requirementType None => before
			("setup", None, "installed", None),
			[("product1", "setup"), ("product3", "setup"), ("product2", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "not_installed", "none")],
			# productAction "setup" requires installationStatus "installed" after
			("setup", None, "installed", "after"),
			[("product1", "setup"), ("product2", "setup"), ("product3", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "not_installed", "none")],
			# productAction "setup" requires actionRequest "setup" before
			("setup", "setup", None, "before"),
			[("product1", "setup"), ("product3", "setup"), ("product2", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "installed", "none")],
			# productAction "setup" requires actionRequest "setup" before
			("setup", "setup", None, "before"),
			[("product1", "setup"), ("product3", "setup"), ("product2", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "installed", "none")],
			# productAction "setup" requires actionRequest "setup" after
			("setup", "setup", None, "after"),
			[("product1", "setup"), ("product2", "setup"), ("product3", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "installed", "none")],
			# productAction "setup" requires installationStatus "not_installed" before (fulfilled)
			("setup", None, "not_installed", "before"),
			[("product1", "setup"), ("product3", "uninstall"), ("product2", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "not_installed", "none")],
			# productAction "setup" requires installationStatus "not_installed" before (fulfilled)
			("setup", None, "not_installed", "before"),
			[("product1", "setup"), ("product2", "setup"), ("product3", "none")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "not_installed", "none")],
			# productAction "setup" requires actionRequest "uninstall" before
			("setup", "uninstall", None, "before"),
			[("product1", "setup"), ("product3", "uninstall"), ("product2", "setup")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "setup"), ("product3", "not_installed", "none")],
			# productAction "setup" requires actionRequest "uninstall" after
			("setup", "uninstall", None, "after"),
			[("product1", "setup"), ("product2", "setup"), ("product3", "uninstall")],
		),
		(
			[("product1", "not_installed", "setup"), ("product2", "not_installed", "uninstall"), ("product3", "not_installed", "none")],
			# productAction "uninstall" requires actionRequest "uninstall" before
			("uninstall", "uninstall", None, "before"),
			[("product1", "setup"), ("product3", "uninstall"), ("product2", "uninstall")],
		),
	),
)
def test_productOnClient_sequence_dependencies(  # pylint: disable=invalid-name,redefined-outer-name,too-many-arguments
	test_client: OpsiconfdTestClient,
	poc_status: list[tuple[str, str, str]],
	requirement: tuple[str | None, str | None, str | None, str | None],
	expected_actions: list[tuple[str, str]],
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_on_clients = _prepare_product_on_client_sequence_dependencies(
		test_client=test_client, poc_status=poc_status, requirement=requirement
	)
	# print("-------------------------------------------------------------------")
	# print(poc_status)
	# print(requirement)
	# print(expected_actions)
	# print("-------------------------------------------------------------------")
	# pprint([poc.to_hash() for poc in product_on_clients])
	# print("-------------------------------------------------------------------")

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productOnClient_addDependencies",
		"params": [[poc.to_hash() for poc in product_on_clients]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	pocs = res["result"]
	pprint(pocs)
	assert len(pocs) == len(expected_actions)
	for idx, expected in enumerate(expected_actions):
		assert pocs[idx]["productId"] == f"test-backend-rpc-{expected[0]}"
		assert pocs[idx]["actionRequest"] == expected[1]


def test_setProductActionRequestWithDependencies(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	client_id = "test-client.opsi.org"
	depot_id = get_depotserver_id()
	product1 = {
		"name": "citrixworkspaceapp",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": 0,
		"id": "citrixworkspaceapp",
		"productVersion": "22.12.0.48or22.3.2000.2105",
		"packageVersion": "8",
		"type": "LocalbootProduct",
	}
	product2 = {
		"name": "citrix",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": 0,
		"id": "citrix",
		"productVersion": "14.12.0.18020",
		"packageVersion": "35",
		"type": "LocalbootProduct",
	}
	product_dependency1 = {
		"productId": "citrixworkspaceapp",
		"productType": "LocalbootProduct",
		"productVersion": "22.12.0.48or22.3.2000.2105",
		"packageVersion": "8",
		"productAction": "setup",
		"requiredProductId": "citrix",
		"requiredInstallationStatus": "not_installed",
		"requirementType": "before",
	}
	product_dependency2 = {
		"productId": "citrix",
		"productType": "LocalbootProduct",
		"productVersion": "14.12.0.18020",
		"packageVersion": "35",
		"productAction": "setup",
		"requiredProductId": "citrixworkspaceapp",
		"requiredInstallationStatus": "not_installed",
		"requirementType": "before",
	}
	product_on_depot1 = {
		"productId": "citrixworkspaceapp",
		"productType": "LocalbootProduct",
		"productVersion": "22.12.0.48or22.3.2000.2105",
		"packageVersion": "8",
		"depotId": depot_id,
	}
	product_on_depot2 = {
		"productId": "citrix",
		"productType": "LocalbootProduct",
		"productVersion": "14.12.0.18020",
		"packageVersion": "35",
		"depotId": depot_id,
	}

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createOpsiClient", "params": [client_id]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_createObjects", "params": [[product1, product2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_createObjects", "params": [[product_dependency1, product_dependency2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_createObjects", "params": [[product_on_depot1, product_on_depot2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "setProductActionRequestWithDependencies", "params": [product1["id"], client_id, "setup"]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
