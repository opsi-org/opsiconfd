# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_license_on_client
"""

from opsicommon.objects import (
	LicenseContract,
	LicensePool,
	OEMSoftwareLicense,
	OpsiClient,
	SoftwareLicenseToLicensePool,
)

from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	test_client,
)

from .test_obj_product import create_test_products


def test_licenseOnClient_getOrCreateObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)
	pool1 = LicensePool(id="test-pool-1", description="Test pool", productIds=[product1["id"], product2["id"]])
	contract1 = LicenseContract(id="test-contract-1", description="test contract")
	license1 = OEMSoftwareLicense(id="test-license-1", licenseContractId=contract1.id, maxInstallations=1)
	lic2pool = SoftwareLicenseToLicensePool(softwareLicenseId=license1.id, licensePoolId=pool1.id, licenseKey="key")
	client1 = OpsiClient(id="test-client-1.opsi.org")
	client2 = OpsiClient(id="test-client-2.opsi.org")
	rpcs = [
		{"jsonrpc": "2.0", "id": 1, "method": "licensePool_createObjects", "params": [pool1.to_hash()]},
		{"jsonrpc": "2.0", "id": 2, "method": "licenseContract_createObjects", "params": [contract1.to_hash()]},
		{"jsonrpc": "2.0", "id": 3, "method": "softwareLicense_createObjects", "params": [license1.to_hash()]},
		{"jsonrpc": "2.0", "id": 4, "method": "softwareLicenseToLicensePool_createObjects", "params": [lic2pool.to_hash()]},
		{"jsonrpc": "2.0", "id": 5, "method": "host_createObjects", "params": [[client1.to_hash(), client2.to_hash()]]},
	]
	response = test_client.post("/rpc", json=rpcs).json()
	assert len(response) == 5
	for res in response:
		assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "licenseOnClient_getOrCreateObject",
		"params": {"clientId": client1.id, "productId": product1["id"]},
	}
	response = test_client.post("/rpc", json=rpc).json()
	assert "error" not in response

	res = response["result"]
	assert res["type"] == "LicenseOnClient"
	assert res["licenseKey"] == lic2pool.licenseKey
	assert res["softwareLicenseId"] == license1.id
	assert res["licensePoolId"] == pool1.id
	assert res["clientId"] == client1.id

	response = test_client.post("/rpc", json=rpc).json()
	assert "error" not in response
	assert res["softwareLicenseId"] == license1.id
	assert res["licenseKey"] == lic2pool.licenseKey

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "licenseOnClient_getOrCreateObject",
		"params": {"clientId": client2.id, "productId": product1["id"]},
	}
	response = test_client.post("/rpc", json=rpc).json()
	assert response["error"]["data"]["class"] == "LicenseMissingError"
