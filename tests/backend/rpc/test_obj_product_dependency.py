# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product_dependency
"""

from opsicommon.objects import LocalbootProduct, ProductDependency, ProductOnClient, ProductOnDepot

from opsiconfd.config import get_depotserver_id
from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Connection,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_redis,
	database_connection,
	get_config,
	test_client,
)

from .test_obj_product import create_test_products
from .utils import cleanup_database  # pylint: disable=unused-import


def test_get_product_action_groups(  # pylint: disable=redefined-outer-name,too-many-locals,too-many-statements
	backend: UnprotectedBackend,
) -> None:
	client_id = "test-client.opsi.org"
	depot_id = get_depotserver_id()

	product1 = LocalbootProduct(
		id="opsi-client-agent", productVersion="4.3.0.0", packageVersion="1", priority=95, setupScript="setup.opsiscript"
	)
	product2 = LocalbootProduct(id="someapp6", productVersion="6.0", packageVersion="1", priority=0, setupScript="setup.opsiscript")
	product3 = LocalbootProduct(id="someapp7", productVersion="7.0", packageVersion="1", priority=10, setupScript="setup.opsiscript")
	product4 = LocalbootProduct(id="someapp-config", productVersion="7.0", packageVersion="1", priority=20, setupScript="setup.opsiscript")
	product5 = LocalbootProduct(id="firefox", productVersion="115.0.2", packageVersion="1", priority=-80, setupScript="setup.opsiscript")
	product6 = LocalbootProduct(id="firefox-addon1", productVersion="1.0", packageVersion="1", priority=-10, setupScript="setup.opsiscript")
	product_dependency1 = ProductDependency(
		productId="someapp6",
		productVersion="6.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp7",
		requiredInstallationStatus="not_installed",
		requirementType="before",
	)
	product_dependency2 = ProductDependency(
		productId="someapp6",
		productVersion="6.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp-config",
		requiredAction="setup",
		requirementType="after",
	)
	product_dependency3 = ProductDependency(
		productId="someapp7",
		productVersion="7.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp6",
		requiredInstallationStatus="not_installed",
	)

	product_dependency4 = ProductDependency(
		productId="someapp7",
		productVersion="7.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp-config",
		requiredAction="setup",
		requirementType="after",
	)
	product_dependency5 = ProductDependency(
		productId="firefox-addon1",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="firefox",
		requiredProductVersion="115.0.2",
		requiredPackageVersion="1",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency6 = ProductDependency(
		productId="firefox-addon1",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="not-available",
		requiredProductVersion="1.0",
		requiredPackageVersion="1",
		requiredAction="setup",
		requirementType="after",
	)
	product_on_depot1 = ProductOnDepot(
		productId="opsi-client-agent", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot2 = ProductOnDepot(
		productId="someapp6", productType="localboot", productVersion="6.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot3 = ProductOnDepot(
		productId="someapp7", productType="localboot", productVersion="7.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot4 = ProductOnDepot(
		productId="someapp-config", productType="localboot", productVersion="7.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot5 = ProductOnDepot(
		productId="firefox", productType="localboot", productVersion="115.0.2", packageVersion="1", depotId=depot_id
	)
	product_on_depot6 = ProductOnDepot(
		productId="firefox-addon1", productType="localboot", productVersion="1.0", packageVersion="1", depotId=depot_id
	)
	product_on_client_be_1 = ProductOnClient(
		productId="someapp6",
		productType="localboot",
		productVersion="6.0",
		packageVersion="1",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="none",
	)
	product_on_client_be_2 = ProductOnClient(
		productId="firefox",
		productType="localboot",
		productVersion="111.1.1",
		packageVersion="1",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="none",
	)
	backend.host_createOpsiClient(id=client_id)
	backend.product_createObjects([product1, product2, product3, product4, product5, product6])
	backend.productDependency_createObjects(
		[product_dependency1, product_dependency2, product_dependency3, product_dependency4, product_dependency5, product_dependency6]
	)
	backend.productOnDepot_createObjects(
		[product_on_depot1, product_on_depot2, product_on_depot3, product_on_depot4, product_on_depot5, product_on_depot6]
	)
	backend.productOnClient_createObjects([product_on_client_be_1, product_on_client_be_2])
	product_on_client_1 = ProductOnClient(
		productId="opsi-client-agent",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_2 = ProductOnClient(
		productId="someapp7",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_3 = ProductOnClient(
		productId="firefox-addon1",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)

	res = backend.get_product_action_groups(  # type: ignore[misc]
		[product_on_client_3, product_on_client_1, product_on_client_2],
	)[client_id]

	assert res[0].priority == 95
	assert len(res[0].product_on_clients) == 1
	assert res[0].product_on_clients[0].productId == "opsi-client-agent"
	assert res[0].product_on_clients[0].actionRequest == "setup"
	assert res[0].product_on_clients[0].actionSequence == 0

	assert res[1].priority == 0
	assert len(res[1].product_on_clients) == 3
	assert res[1].product_on_clients[0].productId == "someapp6"
	assert res[1].product_on_clients[0].actionRequest == "uninstall"
	assert res[1].product_on_clients[0].actionSequence == 1
	assert res[1].product_on_clients[1].productId == "someapp7"
	assert res[1].product_on_clients[1].actionRequest == "setup"
	assert res[1].product_on_clients[1].actionSequence == 2
	assert res[1].product_on_clients[2].productId == "someapp-config"
	assert res[1].product_on_clients[2].actionRequest == "setup"
	assert res[1].product_on_clients[2].actionSequence == 3

	assert res[2].priority == -80
	assert len(res[2].product_on_clients) == 2
	assert res[2].product_on_clients[0].productId == "firefox"
	assert res[2].product_on_clients[0].actionRequest == "setup"
	assert res[2].product_on_clients[0].actionSequence == 4
	assert res[2].product_on_clients[1].productId == "firefox-addon1"
	assert res[2].product_on_clients[1].actionRequest == "setup"
	assert res[2].product_on_clients[1].actionSequence == 5

	res2 = backend.productOnClient_generateSequence([product_on_client_3, product_on_client_1, product_on_client_2])
	assert len(res2) == 3
	assert res2[0].productId == "opsi-client-agent"
	assert res2[0].actionRequest == "setup"
	assert res2[0].actionSequence == 0
	assert res2[1].productId == "someapp7"
	assert res2[1].actionRequest == "setup"
	assert res2[1].actionSequence == 2
	assert res2[2].productId == "firefox-addon1"
	assert res2[2].actionRequest == "setup"
	assert res2[2].actionSequence == 5

	res2 = backend.productOnClient_addDependencies([product_on_client_3, product_on_client_1, product_on_client_2])
	assert len(res2) == 6
	assert res2[0].productId == "opsi-client-agent"
	assert res2[0].actionRequest == "setup"
	assert res2[0].actionSequence == 0
	assert res2[1].productId == "someapp6"
	assert res2[1].actionRequest == "uninstall"
	assert res2[1].actionSequence == 1
	assert res2[2].productId == "someapp7"
	assert res2[2].actionRequest == "setup"
	assert res2[2].actionSequence == 2
	assert res2[3].productId == "someapp-config"
	assert res2[3].actionRequest == "setup"
	assert res2[3].actionSequence == 3
	assert res2[4].productId == "firefox"
	assert res2[4].actionRequest == "setup"
	assert res2[4].actionSequence == 4
	assert res2[5].productId == "firefox-addon1"
	assert res2[5].actionRequest == "setup"
	assert res2[5].actionSequence == 5

	# Match required version
	product_on_client_be_2 = ProductOnClient(
		productId="firefox",
		productType="localboot",
		productVersion="115.0.2",
		packageVersion="1",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="none",
	)
	backend.productOnClient_createObjects([product_on_client_be_2])

	res = backend.get_product_action_groups(  # type: ignore[misc]
		[product_on_client_3, product_on_client_1, product_on_client_2],
	)[client_id]

	assert res[2].priority == -10
	assert len(res[2].product_on_clients) == 1
	assert res[2].product_on_clients[0].productId == "firefox-addon1"
	assert res[2].product_on_clients[0].actionRequest == "setup"
	assert res[2].product_on_clients[0].actionSequence == 4

	product_ordering = backend.getProductOrdering(depotId=depot_id)
	assert product_ordering["not_sorted"] == ["firefox", "firefox-addon1", "opsi-client-agent", "someapp-config", "someapp6", "someapp7"]
	assert product_ordering["sorted"] == ["opsi-client-agent", "someapp7", "someapp-config", "someapp6", "firefox", "firefox-addon1"]


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

	# productDependency 1 and 2 should be created
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

	# productDependency 1 and 2 should be created
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

	# productDependency 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])


def test_product_dependency_updateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	# product 1 and 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])

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

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_dependency = res["result"][0]
	for attr, val in product_dependency1.items():
		if attr == "requiredAction":
			assert product_dependency[attr] == "none"
		else:
			assert product_dependency[attr] == val

	# No new product dependency should be created.
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

	# update 2 product dependencies
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
