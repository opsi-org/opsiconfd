# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application redis interface
"""

import time
from socket import getfqdn
from unittest import mock

from fastapi import status

from opsiconfd.utils import decode_redis_result
from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	depot_jsonrpc,
	get_config,
	get_dummy_products,
	get_product_ordering_jsonrpc,
	products_jsonrpc,
	sync_redis_client,
	test_client,
)


def test_redis_command(test_client):  # pylint: disable=redefined-outer-name
	res = test_client.post("/redis-interface", auth=(ADMIN_USER, ADMIN_PASS), json={"cmd": "ping"})
	res.raise_for_status()
	assert res.json() == {"result": True}


def test_redis_stats(test_client):  # pylint: disable=redefined-outer-name
	res = test_client.get("/redis-interface/redis-stats", auth=(ADMIN_USER, ADMIN_PASS))
	res.raise_for_status()
	assert res.status_code == 200
	res = res.json()
	assert res["key_info"]


def test_clear_product_cache(test_client):  # pylint: disable=redefined-outer-name
	products = get_dummy_products(10)
	depot_id = "test-depot.uib.local"
	configserver = getfqdn()
	with sync_redis_client() as redis:
		# create products on depot / make sure that the cache is used (jsonrpc_time_to_cache)
		with (
			get_config({"jsonrpc_time_to_cache": 0}),
			depot_jsonrpc(test_client, "", depot_id),
			products_jsonrpc(test_client, "", products, depots=[configserver, depot_id]),
		):
			# get product ordering -> create cache depot and configserver
			get_product_ordering_jsonrpc(test_client, configserver)
			get_product_ordering_jsonrpc(test_client, depot_id)

			time.sleep(5)

			keys_to_check = (
				f"opsiconfd:jsonrpccache:{depot_id}:products",
				f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1",
				f"opsiconfd:jsonrpccache:{depot_id}:products:uptodate",
				f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1:uptodate",
			)

			for key in keys_to_check:
				assert redis.exists(key) == 1

			depots = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
			assert depots == {configserver, depot_id}

			# call clear-product-cache all cache keys for depot_id sould be removed
			body = {"depots": [depot_id]}
			res = test_client.post("/redis-interface/clear-product-cache", auth=(ADMIN_USER, ADMIN_PASS), json=body)
			assert res.status_code == status.HTTP_200_OK

			for key in keys_to_check:
				assert redis.exists(key) == 0

			# depot id sould still be in the cache
			depots = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
			assert depots == {configserver, depot_id}

			# fill cache again
			get_product_ordering_jsonrpc(test_client, depot_id)

			for key in keys_to_check:
				assert redis.exists(key) == 1

			# call clear-product-cache all cache without depot id
			body = {}
			res = test_client.post("/redis-interface/clear-product-cache", auth=(ADMIN_USER, ADMIN_PASS), json=body)
			assert res.status_code == status.HTTP_200_OK

			for key in keys_to_check:
				assert redis.exists(key) == 0

		# depot sould be deleted and removed from cache
		depots = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
		assert depots == {configserver}


def test_clear_product_cache_error(test_client):  # pylint: disable=redefined-outer-name
	products = get_dummy_products(10)
	configserver = getfqdn()
	with (
		get_config({"jsonrpc_time_to_cache": 0}),
		products_jsonrpc(test_client, "", products, depots=[configserver]),
	):

		body = {"depots": [configserver]}
		with mock.patch("aioredis.client.Redis.pipeline", side_effect=Exception("Redis test error")):
			res = test_client.post("/redis-interface/clear-product-cache", auth=(ADMIN_USER, ADMIN_PASS), json=body)
		assert res.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
		assert res.json() == {
			"status": 500,
			"class": "Exception",
			"code": None,
			"message": "Error while reading redis data",
			"details": "Redis test error",
		}


async def test_get_depot_cache(test_client):  # pylint: disable=redefined-outer-name
	depot_id = "test-get.depot.cache"
	products = (
		{"id": "test_product1", "name": "Test Product 1", "productVersion": "1.0", "packageVersion": "1", "priority": 95},
		{"id": "test_product2", "name": "Test Product 2", "productVersion": "1.0", "packageVersion": "1", "priority": 81},
		{"id": "test_product3", "name": "Test Product 3", "productVersion": "1.0", "packageVersion": "1", "priority": 90},
	)
	with (
		get_config({"jsonrpc_time_to_cache": 0}),
		depot_jsonrpc(test_client, "", depot_id),  # Create depot
		products_jsonrpc(test_client, "", products, [depot_id]),  # Create products
	):
		get_product_ordering_jsonrpc(test_client, depot_id)

		res = test_client.get("/redis-interface/depot-cache", auth=(ADMIN_USER, ADMIN_PASS))
		res.raise_for_status()
		res = res.json()
		assert depot_id in res["depots"]

		res = test_client.get("/redis-interface/products", auth=(ADMIN_USER, ADMIN_PASS))
		res.raise_for_status()
		res = res.json()
		assert len(res[depot_id]) == len(products)


def test_get_depot_cache_confgserver(test_client):  # pylint: disable=redefined-outer-name
	products = get_dummy_products(10)
	configserver = getfqdn()
	with (
		get_config({"jsonrpc_time_to_cache": 0}),
		products_jsonrpc(test_client, "", products, depots=[configserver]),
	):
		get_product_ordering_jsonrpc(test_client, configserver)

		body = {"depots": [configserver]}

		res = test_client.get("/redis-interface/depot-cache", auth=(ADMIN_USER, ADMIN_PASS), json=body)
		assert res.status_code == status.HTTP_200_OK
		assert res.json() == {"depots": [configserver]}


def test_get_depot_cache_error(test_client):  # pylint: disable=redefined-outer-name
	products = get_dummy_products(10)
	configserver = getfqdn()
	with (
		get_config({"jsonrpc_time_to_cache": 0}),
		products_jsonrpc(test_client, "", products, depots=[configserver]),
	):
		get_product_ordering_jsonrpc(test_client, configserver)

		body = {"depots": [configserver]}
		with mock.patch("opsiconfd.utils.decode_redis_result", side_effect=Exception("Redis test error")):
			res = test_client.get("/redis-interface/depot-cache", auth=(ADMIN_USER, ADMIN_PASS), json=body)
		assert res.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
		assert res.json() == {
			"status": 500,
			"class": "Exception",
			"code": None,
			"message": "Error while reading redis data",
			"details": "Redis test error",
		}


def test_get_products(test_client):  # pylint: disable=redefined-outer-name
	products = get_dummy_products(10)
	configserver = getfqdn()
	product_ids = [p["id"] for p in products]
	with (
		get_config({"jsonrpc_time_to_cache": 0}),
		products_jsonrpc(test_client, "", products, depots=[configserver]),
	):
		get_product_ordering_jsonrpc(test_client, configserver)

		body = {"depots": [configserver]}
		res = test_client.get("/redis-interface/products", auth=(ADMIN_USER, ADMIN_PASS), json=body)
		assert res.status_code == status.HTTP_200_OK
		assert res.json() == {configserver: product_ids}


def test_get_products_error(test_client):  # pylint: disable=redefined-outer-name
	with mock.patch("opsiconfd.utils.decode_redis_result", side_effect=Exception("Redis test error")):
		res = test_client.get("/redis-interface/products", auth=(ADMIN_USER, ADMIN_PASS), json={})
	assert res.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
	assert res.json() == {
		"status": 500,
		"class": "Exception",
		"code": None,
		"message": "Error while reading redis data",
		"details": "Redis test error",
	}
