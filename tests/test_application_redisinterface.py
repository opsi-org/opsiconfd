# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.redisinterface
"""

from .utils import (  # pylint: disable=unused-import
	clean_redis, config, get_config, ADMIN_USER, ADMIN_PASS,
	products_jsonrpc, depot_jsonrpc, get_product_ordering_jsonrpc
)


def test_redis_command(test_client):
	res = test_client.post("/redis-interface", auth=(ADMIN_USER, ADMIN_PASS), json={"cmd": "ping"})
	res.raise_for_status()
	assert res.json() == {"status": 200, "error": None, "data": {"result": True}}


def test_redis_stats(test_client):
	res = test_client.get("/redis-interface/redis-stats", auth=(ADMIN_USER, ADMIN_PASS))
	res.raise_for_status()
	res = res.json()
	assert res["status"] == 200
	assert res["data"]
	assert res["data"]["key_info"]


async def test_get_depot_cache(test_client):  # pylint: disable=redefined-outer-name
	depot_id = "test-get.depot.cache"
	products = [
		{"id": "test_product1", "name": "Test Product 1", "productVersion": "1.0", "packageVersion": "1", "priority": 95},
		{"id": "test_product2", "name": "Test Product 2", "productVersion": "1.0", "packageVersion": "1", "priority": 81},
		{"id": "test_product3", "name": "Test Product 3", "productVersion": "1.0", "packageVersion": "1", "priority": 90}
	]
	with (
		get_config({"jsonrpc_time_to_cache": 0}),
		depot_jsonrpc(test_client, "", depot_id),  # Create depot
		products_jsonrpc(test_client, "", products, [depot_id]),  # Create products
	):
		get_product_ordering_jsonrpc(test_client, depot_id)

		res = test_client.get("/redis-interface/depot-cache", auth=(ADMIN_USER, ADMIN_PASS))
		res.raise_for_status()
		res = res.json()
		assert depot_id in res["data"]["depots"]

		res = test_client.get("/redis-interface/products", auth=(ADMIN_USER, ADMIN_PASS))
		res.raise_for_status()
		res = res.json()
		assert len(res["data"][depot_id]) == len(products)
