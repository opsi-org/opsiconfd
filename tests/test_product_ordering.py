# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
product ordering tests
"""

import json
import threading
from typing import List, Dict

import requests

from opsiconfd.utils import decode_redis_result

from .utils import (  # pylint: disable=unused-import
	config, get_config, clean_redis,
	sync_redis_client, products_jsonrpc, delete_products_jsonrpc, depot_jsonrpc,
	get_dummy_products, get_product_ordering_jsonrpc,
	ADMIN_USER, ADMIN_PASS
)


def test_renew_cache_on_delete_products(test_client):  # pylint: disable=redefined-outer-name
	depot_id = "test-product-ordering-depot.uib.gmbh"
	products = get_dummy_products(100)

	with (
		get_config({"jsonrpc_time_to_cache": 0}) as conf,
		depot_jsonrpc(test_client, "", depot_id),
		products_jsonrpc(test_client, "", products, [depot_id]),  # Create products
		sync_redis_client(conf.redis_internal_url) as redis
	):

		# Execution of method getProductOrdering will fill the product ordering cache
		get_product_ordering_jsonrpc(test_client, depot_id)

		# Assert product ordering is cached
		data = redis.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1", 0, -1)
		cached_sorted_products = decode_redis_result(data)
		for product in products:
			assert product["id"] in cached_sorted_products

		# Execution of method product_deleteObjects will invalidate the product ordering cache
		threads = []
		new_products = []
		delete_products = []
		for idx, product in enumerate(products):
			if idx in (3, 23, 45, 77, 89):
				delete_products.append(product)
				threads.append(
					threading.Thread(
						target=delete_products_jsonrpc,
						args=(test_client, "", [products[idx]])
					)
				)
			else:
				new_products.append(product)
		products = new_products
		for thread in threads:
			thread.start()
		for thread in threads:
			thread.join()

		get_product_ordering_jsonrpc(test_client, depot_id)

		# Assert product ordering is cache was updated
		data = redis.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1", 0, -1)
		cached_sorted_products = decode_redis_result(data)
		for product in products:
			assert product["id"] in cached_sorted_products
		for product in delete_products:
			assert product["id"] not in cached_sorted_products


def test_renew_cache_on_create_products(test_client):  # pylint: disable=redefined-outer-name
	depot_id = "test-product-ordering-depot.uib.gmbh"
	products = get_dummy_products(100)
	additional_products = [
		{"id": "test_product01", "name": "Test Product 01", "productVersion": "1.0", "packageVersion": "1", "priority": 80},
		{"id": "test_product02", "name": "Test Product 02", "productVersion": "1.0", "packageVersion": "1", "priority": 81},
	]

	with (
		get_config({"jsonrpc_time_to_cache": 0}) as conf,
		depot_jsonrpc(test_client, "", depot_id),
		sync_redis_client(conf.redis_internal_url) as redis
	):
		with products_jsonrpc(test_client, "", products, [depot_id]):  # Create products
			# Execution of method getProductOrdering will fill the product ordering cache
			get_product_ordering_jsonrpc(test_client, depot_id)

			# Assert product ordering is cached
			data = redis.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1", 0, -1)
			cached_sorted_products = decode_redis_result(data)
			for product in products:
				assert product["id"] in cached_sorted_products

			# Add new products
			with products_jsonrpc(test_client, "", additional_products, [depot_id]):
				get_product_ordering_jsonrpc(test_client, depot_id)

				# Assert product ordering cache was updated
				data = redis.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1", 0, -1)
				cached_sorted_products = decode_redis_result(data)
				for product in additional_products:
					assert product["id"] in cached_sorted_products

		# All created products are now deleted again, cache should be invalid
		uptodate = redis.get(f"opsiconfd:jsonrpccache:{depot_id}:products:uptodate")
		assert uptodate is None

		uptodate_algorithm1 = redis.get(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1:uptodate")
		assert uptodate_algorithm1 is None

		# Execution of method getProductOrdering will fill the product ordering cache again
		result = get_product_ordering_jsonrpc(test_client, depot_id)
		for product in products + additional_products:
			assert product["id"] not in result["sorted"]
			assert product["id"] not in result["not_sorted"]


def test_getProductOrdering(test_client):  # pylint: disable=invalid-name,redefined-outer-name
	depot_id = "test-product-ordering-depot.uib.gmbh"
	products = [
		{"id": "test_product1", "name": "Test Product 1", "productVersion": "1.0", "packageVersion": "1", "priority": 95},
		{"id": "test_product2", "name": "Test Product 2", "productVersion": "1.0", "packageVersion": "1", "priority": 81},
		{"id": "test_product3", "name": "Test Product 3", "productVersion": "1.0", "packageVersion": "1", "priority": 90}
	]
	products_sorted = ["test_product1", "test_product3", "test_product2"]
	with (
		get_config({"jsonrpc_time_to_cache": 0}) as conf,
		sync_redis_client(conf.redis_internal_url) as redis,
		depot_jsonrpc(test_client, "", depot_id),  # Create depot
	):
		with products_jsonrpc(test_client, "", products, [depot_id]):  # Create products
			data = redis.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1", 0, -1)
			cached_sorted_products = decode_redis_result(data)
			assert cached_sorted_products == []

			# Execution of method getProductOrdering will fill the product ordering cache
			result = get_product_ordering_jsonrpc(test_client, depot_id)
			for product in products:
				assert product["id"] in result["sorted"]
				assert product["id"] in result["not_sorted"]
			assert products_sorted == result["sorted"]

			# Mark cache as outdated
			with redis.pipeline() as pipe:
				pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:uptodate")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1:uptodate")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm2:uptodate")
				pipe.execute()

			# Execution of method getProductOrdering will fill the product ordering cache
			result = get_product_ordering_jsonrpc(test_client, depot_id)
			for product in products:
				assert product["id"] in result["sorted"]
				assert product["id"] in result["not_sorted"]

		# Product are deleted
		result = get_product_ordering_jsonrpc(test_client, depot_id)
		assert len(result["sorted"]) == 0
		assert len(result["not_sorted"]) == 0
