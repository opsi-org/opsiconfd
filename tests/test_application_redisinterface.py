# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test application redis interface
"""

import time

from fastapi import status

from opsiconfd.config import get_configserver_id
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	depot_jsonrpc,
	get_dummy_products,
	get_product_ordering_jsonrpc,
	products_jsonrpc,
	test_client,
)


def test_redis_command(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.post("/redis-interface", auth=(ADMIN_USER, ADMIN_PASS), json={"cmd": "ping"})
	res.raise_for_status()
	assert res.json() == {"result": True}


def test_redis_stats(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.get("/redis-interface/redis-stats", auth=(ADMIN_USER, ADMIN_PASS))
	res.raise_for_status()
	assert res.status_code == 200
	assert res.json()["key_info"]


def test_clear_rpc_cache(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	products = get_dummy_products(10)
	depot_id = "test-depot.uib.local"
	configserver = get_configserver_id()
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with (
		depot_jsonrpc(test_client, "", depot_id),
		products_jsonrpc(test_client, "", products, depots=[configserver, depot_id]),
	):
		# Get product ordering -> create two cache entries
		get_product_ordering_jsonrpc(test_client, configserver)
		get_product_ordering_jsonrpc(test_client, depot_id)

		time.sleep(1)

		res = test_client.get("/redis-interface/load-rpc-cache-info")
		assert res.status_code == status.HTTP_200_OK
		assert res.json()["result"]["product_ordering"] == 2

		# Call clear-product-cache all cache keys for depot_id sould be removed
		body = {"cache_name": "product_ordering"}
		res = test_client.post("/redis-interface/clear-rpc-cache", json=body)
		assert res.status_code == status.HTTP_200_OK

		res = test_client.get("/redis-interface/load-rpc-cache-info")
		assert res.status_code == status.HTTP_200_OK
		assert "product_ordering" not in res.json()["result"]
