# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd.backend.rpc.obj_license_pool
"""


from opsicommon.objects import LicensePool

from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	get_config,
	test_client,
)

from .test_obj_product import create_test_products


def test_licensePool_insert_get_delete(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product1, product2 = create_test_products(test_client)
	pool = LicensePool(id="test-backend-rpc-license-pool-1", description="License pool", productIds=[product1["id"], product2["id"]])

	# Create pool
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "licensePool_insertObject", "params": [pool.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "licensePool_getObjects", "params": [[], {"productIds": [product1["id"], product2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		{
			"description": pool.description,
			"productIds": [product1["id"], product2["id"]],
			"id": pool.id,
			"type": "LicensePool",
			"ident": pool.id,
		}
	]

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "licensePool_deleteObjects", "params": [pool.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "licensePool_getObjects", "params": []}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == []
