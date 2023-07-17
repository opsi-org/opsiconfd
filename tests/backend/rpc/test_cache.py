# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.cache
"""

import time
from threading import Thread
from unittest.mock import patch

from opsiconfd.backend.rpc.cache import (
	rpc_cache_clear,
	rpc_cache_info,
	rpc_cache_load,
	rpc_cache_store,
)
from tests.utils import (  # pylint: disable=unused-import
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	delete_products_jsonrpc,
	depot_jsonrpc,
	get_dummy_products,
	get_product_ordering_jsonrpc,
	products_jsonrpc,
	test_client,
)


def test_cache_store_load_clear_info() -> None:
	assert rpc_cache_load("cache1", "param1", param2=2) is None
	assert not rpc_cache_info()

	result_1_1 = {"some": "result", "to": "cache"}
	rpc_cache_store("cache1", result_1_1, "param1", param2=2)
	assert rpc_cache_load("cache1", "param1", param2=2) == result_1_1

	assert rpc_cache_load("cache1", "param1", 2) is None

	result_1_2 = {"some": "other_result", "list": [1, 2, 3]}
	rpc_cache_store("cache1", result_1_2, "param1", 2)

	result_2_1 = {"some": "other_result", "list": [1, 2, 3]}
	rpc_cache_store("cache2", result_2_1)

	assert rpc_cache_load("cache1", "param1", param2=2) == result_1_1
	assert rpc_cache_load("cache1", "param1", 2) == result_1_2
	assert rpc_cache_load("cache2") == result_2_1

	assert rpc_cache_info() == {"cache1": 2, "cache2": 1}
	rpc_cache_clear("cache1")
	assert rpc_cache_load("cache1", "param1", param2=2) is None
	assert rpc_cache_load("cache1", "param1", 2) is None
	assert rpc_cache_load("cache2") == result_2_1
	assert rpc_cache_info() == {"cache2": 1}

	rpc_cache_clear("cache2")
	assert rpc_cache_load("cache1", "param1", param2=2) is None
	assert rpc_cache_load("cache1", "param1", 2) is None
	assert rpc_cache_load("cache2") is None
	assert not rpc_cache_info()


def test_cache_expiration() -> None:
	with patch("opsiconfd.backend.rpc.cache.CACHE_EXPIRATION", 1):
		result = b"DATA"
		assert rpc_cache_load("cache_test", param=True) is None
		rpc_cache_store("cache_test", result, param=True)
		assert rpc_cache_load("cache_test", param=True) == result
		time.sleep(2)
		assert rpc_cache_load("cache_test", param=True) is None


def test_renew_cache_on_delete_products(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	depot_id = "test-product-ordering-depot.uib.gmbh"
	products = get_dummy_products(100)

	with (
		depot_jsonrpc(test_client, "", depot_id),
		products_jsonrpc(test_client, "", products, [depot_id]),  # Create products
	):
		# Execution of method getProductOrdering will fill the product ordering cache
		get_product_ordering_jsonrpc(test_client, depot_id)

		# Assert product ordering is cached
		cached_sorted_products = rpc_cache_load("product_ordering", depot_id)["sorted"]
		for product in products:
			assert product["id"] in cached_sorted_products

		# Execution of method product_deleteObjects will invalidate the product ordering cache
		threads = []
		new_products = []
		delete_products = []
		for idx, product in enumerate(products):
			if idx in (3, 23, 45, 77, 89):
				delete_products.append(product)
				threads.append(Thread(target=delete_products_jsonrpc, args=(test_client, "", [products[idx]])))
			else:
				new_products.append(product)
		products = new_products
		for thread in threads:
			thread.start()
		for thread in threads:
			thread.join()

		get_product_ordering_jsonrpc(test_client, depot_id)

		# Assert product ordering is cache was updated
		cached_sorted_products = rpc_cache_load("product_ordering", depot_id)["sorted"]
		for product in products:
			assert product["id"] in cached_sorted_products
		for product in delete_products:
			assert product["id"] not in cached_sorted_products


def test_renew_cache_on_create_products(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	depot_id = "test-product-ordering-depot.uib.gmbh"
	products = get_dummy_products(100)
	additional_products = [
		{
			"id": "test_product01",
			"name": "Test Product 01",
			"productVersion": "1.0",
			"packageVersion": "1",
			"priority": 80,
			"setupScript": "setup.opsiscript",
		},
		{
			"id": "test_product02",
			"name": "Test Product 02",
			"productVersion": "1.0",
			"packageVersion": "1",
			"priority": 81,
			"setupScript": "setup.opsiscript",
		},
	]

	with depot_jsonrpc(test_client, "", depot_id):
		with products_jsonrpc(test_client, "", products, [depot_id]):  # Create products
			# Execution of method getProductOrdering will fill the product ordering cache
			get_product_ordering_jsonrpc(test_client, depot_id)

			# Assert product ordering is cached
			cached_sorted_products = rpc_cache_load("product_ordering", depot_id)["sorted"]
			for product in products:
				assert product["id"] in cached_sorted_products

			# Add new products
			with products_jsonrpc(test_client, "", additional_products, [depot_id]):
				get_product_ordering_jsonrpc(test_client, depot_id)

				# Assert product ordering cache was updated
				cached_sorted_products = rpc_cache_load("product_ordering", depot_id)["sorted"]
				for product in additional_products:
					assert product["id"] in cached_sorted_products

		# All created products are now deleted again, cache should be invalid
		assert rpc_cache_load("product_ordering", depot_id) is None

		# Execution of method getProductOrdering will fill the product ordering cache again
		result = get_product_ordering_jsonrpc(test_client, depot_id)
		for product in products + additional_products:
			assert product["id"] not in result["sorted"]
			assert product["id"] not in result["not_sorted"]


def test_get_product_ordering(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	depot_id = "test-product-ordering-depot.uib.gmbh"
	products = [
		{
			"id": "test_product1",
			"name": "Test Product 1",
			"productVersion": "1.0",
			"packageVersion": "1",
			"priority": 95,
			"setupScript": "setup.opsiscript",
		},
		{
			"id": "test_product2",
			"name": "Test Product 2",
			"productVersion": "1.0",
			"packageVersion": "1",
			"priority": 81,
			"setupScript": "setup.opsiscript",
		},
		{
			"id": "test_product3",
			"name": "Test Product 3",
			"productVersion": "1.0",
			"packageVersion": "1",
			"priority": 90,
			"setupScript": "setup.opsiscript",
		},
	]
	products_sorted = ["test_product1", "test_product3", "test_product2"]
	with depot_jsonrpc(test_client, "", depot_id):  # Create depot
		with products_jsonrpc(test_client, "", products, [depot_id]):  # Create products
			assert not rpc_cache_load("product_ordering", depot_id)

			# Execution of method getProductOrdering will fill the product ordering cache
			result = get_product_ordering_jsonrpc(test_client, depot_id)
			for product in products:
				assert product["id"] in result["sorted"]
				assert product["id"] in result["not_sorted"]
			assert products_sorted == result["sorted"]

			cached_sorted_products = rpc_cache_load("product_ordering", depot_id)["sorted"]
			assert cached_sorted_products == products_sorted

			# Get cached data
			result = get_product_ordering_jsonrpc(test_client, depot_id)
			for product in products:
				assert product["id"] in result["sorted"]
				assert product["id"] in result["not_sorted"]

			# Clear cache
			rpc_cache_clear("product_ordering")

			# Execution of method getProductOrdering will fill the product ordering cache
			result = get_product_ordering_jsonrpc(test_client, depot_id)
			for product in products:
				assert product["id"] in result["sorted"]
				assert product["id"] in result["not_sorted"]

			cached_sorted_products = rpc_cache_load("product_ordering", depot_id)["sorted"]
			assert cached_sorted_products == products_sorted

		# Product are deleted
		result = get_product_ordering_jsonrpc(test_client, depot_id)
		assert len(result["sorted"]) == 0
		assert len(result["not_sorted"]) == 0
