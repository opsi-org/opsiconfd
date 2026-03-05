# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.obj_product
"""

import pytest
from opsicommon.objects import (
	ConfigState,
	LocalbootProduct,
	OpsiClient,
	OpsiDepotserver,
	ProductOnClient,
	ProductOnDepot,
	ProductPropertyState,
	UnicodeProductProperty,
)

from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	get_config,
	test_client,
)


def create_test_products(test_client: OpsiconfdTestClient) -> tuple:  # noqa: F811
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
		"type": "NetbootProduct",
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


def test_product_insertObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_product_updateObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_product_getIdents(
	test_client: OpsiconfdTestClient,  # noqa: F811
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

	# test mysql wildcard _ should be escaped
	product3 = {
		"name": "test-backend-rpc-product_3",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": 0,
		"description": "test-backend-rpc-product 3",
		"advice": "Some advice ",
		"id": "test-backend-rpc-product_3",
		"productVersion": "5.3.0",
		"packageVersion": "2",
		"type": "LocalbootProduct",
	}

	# Create product 3
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_insertObject", "params": [product3]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getIdents", "params": [[], {"id": "test-backend-rpc-product_*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [f"{product3['id']};{product3['productVersion']};{product3['packageVersion']}"]

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getIdents", "params": [[], {"id": "test-backend-rpc-product-*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		f"{product1['id']};{product1['productVersion']};{product1['packageVersion']}",
		f"{product2['id']};{product2['productVersion']};{product2['packageVersion']}",
	]


def test_product_delete(
	test_client: OpsiconfdTestClient,  # noqa: F811
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
def test_product_get_hashes(
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_product_purge(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	products = [
		LocalbootProduct(id="product-1", name="product-1", productVersion="1.0", packageVersion="1"),
		LocalbootProduct(id="product-2", name="product-2", productVersion="2.0", packageVersion="2"),
	]
	product_properties = [
		UnicodeProductProperty(
			productId=product.id,
			productVersion=product.productVersion,
			packageVersion=product.packageVersion,
			propertyId="prop1",
			defaultValues=["default-value"],
		)
		for product in products
	]
	depots = [
		OpsiDepotserver(id="depot1.opsi.test"),
		OpsiDepotserver(id="depot2.opsi.test"),
		OpsiDepotserver(id="depot3.opsi.test"),
	]
	clients = [
		OpsiClient(id="client1.opsi.test"),
		OpsiClient(id="client2.opsi.test"),
		OpsiClient(id="client3.opsi.test"),
	]
	product_on_depots = [
		ProductOnDepot(
			productId=product.id,
			productType=product.getType(),
			productVersion=product.productVersion,
			packageVersion=product.packageVersion,
			depotId=depot.id,
		)
		for product in products
		for depot in depots
	]
	product_on_clients = [
		ProductOnClient(
			productId=product.id,
			productType=product.getType(),
			productVersion=product.productVersion,
			packageVersion=product.packageVersion,
			clientId=client.id,
			installationStatus="installed",
			actionRequest="none",
		)
		for product in products
		for client in clients
	]
	product_property_states = [
		ProductPropertyState(
			productId=product.id,
			propertyId="prop1",
			objectId=client.id,
			values=["client-value"],
		)
		for product in products
		for client in clients
	]
	config_states = [
		ConfigState(configId="clientconfig.depot.id", objectId="client1.opsi.test", values=["depot1.opsi.test"]),
		ConfigState(configId="clientconfig.depot.id", objectId="client2.opsi.test", values=["depot2.opsi.test"]),
		ConfigState(configId="clientconfig.depot.id", objectId="client3.opsi.test", values=["depot3.opsi.test"]),
	]

	backend.host_createObjects(depots + clients)
	backend.product_createObjects(products)
	backend.productOnDepot_createObjects(product_on_depots)
	backend.productOnClient_createObjects(product_on_clients)
	backend.productProperty_createObjects(product_properties)
	backend.productPropertyState_createObjects(product_property_states)
	backend.configState_createObjects(config_states)

	assert sorted(backend.configState_getClientToDepotserver(), key=lambda x: (x["clientId"], x["depotId"])) == [
		{"alternativeDepotIds": [], "depotId": "depot1.opsi.test", "clientId": "client1.opsi.test"},
		{"alternativeDepotIds": [], "depotId": "depot2.opsi.test", "clientId": "client2.opsi.test"},
		{"alternativeDepotIds": [], "depotId": "depot3.opsi.test", "clientId": "client3.opsi.test"},
	]

	def asssert_client_objects(product_ids: list[str], client_ids_exist: list[str], client_ids_miss: list[str]) -> None:
		client_ids_exist.sort()
		client_ids_miss.sort()
		pocs = sorted(
			backend.productOnClient_getIdents(returnType="dict", productId=product_ids), key=lambda x: (x["clientId"], x["productId"])
		)
		for client_id in client_ids_exist:
			for product_id in product_ids:
				assert {"productId": product_id, "productType": "LocalbootProduct", "clientId": client_id} in pocs
		for client_id in client_ids_miss:
			for product_id in product_ids:
				assert {"productId": product_id, "productType": "LocalbootProduct", "clientId": client_id} not in pocs

		ppss = sorted(
			backend.productPropertyState_getIdents(returnType="dict", productId=product_ids), key=lambda x: (x["objectId"], x["productId"])
		)
		for client_id in client_ids_exist:
			for product_id in product_ids:
				assert {"objectId": client_id, "productId": product_id, "propertyId": "prop1"} in ppss
		for client_id in client_ids_miss:
			for product_id in product_ids:
				assert {"objectId": client_id, "productId": product_id, "propertyId": "prop1"} not in ppss

	# Assert all objects are present
	asssert_client_objects([p.id for p in products], [c.id for c in clients], [])

	# Purge all products
	for purge_ids in ([], ["product-1", "product-2"], ["product-1"], ["product-2"]):
		backend.product_purge(purge_ids)
		# Assert all objects are present because all products are installed on all depots
		asssert_client_objects([p.id for p in products], [c.id for c in clients], [])

	# Remove product-1 from depot1
	backend.productOnDepot_delete(productId="product-1", depotId="depot1.opsi.test")
	backend.product_purge(["product-1"])
	# Assert objects for product-1 are removed from clients assigned to depot1
	asssert_client_objects(
		["product-1"],
		["client2.opsi.test", "client3.opsi.test"],
		["client1.opsi.test"],
	)
	# Assert objects for product-2 are still present
	asssert_client_objects(
		["product-2"],
		["client1.opsi.test", "client2.opsi.test", "client3.opsi.test"],
		[],
	)

	# Remove product-1 from depot2
	backend.productOnDepot_delete(productId="product-1", depotId="depot2.opsi.test")
	# Objects for product-1 should still be present before purge
	asssert_client_objects(
		["product-1"],
		["client2.opsi.test"],
		[],
	)
	# Purge all products
	backend.product_purge([])
	# Assert all objects for product-1 and client2 are removed
	asssert_client_objects(
		["product-1"],
		[],
		["client2.opsi.test"],
	)
	asssert_client_objects(
		["product-2"],
		["client1.opsi.test", "client2.opsi.test", "client3.opsi.test"],
		[],
	)

	# Remove all products from all depots
	backend.productOnDepot_delete(
		productId=["product-1", "product-2"], depotId=["depot1.opsi.test", "depot2.opsi.test", "depot3.opsi.test"]
	)
	backend.product_purge(["product-1"])
	asssert_client_objects(
		["product-2"],
		["client1.opsi.test", "client2.opsi.test", "client3.opsi.test"],
		[],
	)
	asssert_client_objects(
		["product-1"],
		[],
		["client1.opsi.test", "client2.opsi.test", "client3.opsi.test"],
	)
	backend.product_purge([])
	asssert_client_objects(
		["product-1", "product-2"],
		[],
		["client1.opsi.test", "client2.opsi.test", "client3.opsi.test"],
	)
