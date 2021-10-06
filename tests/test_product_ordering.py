# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
productOrdering tests
"""

import os
import json
import threading
import asyncio
import pytest
import aredis
import requests

from opsiconfd.utils import decode_redis_result

from .utils import (  # pylint: disable=unused-import
	create_depot_rpc, clean_redis, disable_request_warning, config, database_connection,
	ADMIN_USER, ADMIN_PASS, OPSI_SESSION_KEY
)


def delete_product(product, opsi_url):
	delete_products([product], opsi_url)
	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{opsi_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	res.raise_for_status()


@pytest.mark.asyncio
async def test_delete_product(config, database_connection):  # pylint: disable=redefined-outer-name
	db_remove_dummy_products(database_connection)
	create_depot_rpc(config.internal_url, "testdepot.uib.gmbh")
	fill_db(database_connection)

	test_products_sorted = read_sorted_products()

	thread_one = threading.Thread(name="1", target=delete_product, args=({"id": "dummy-prod-1039", "product_version": "1.0", "package_version": "1"},config.internal_url)) # pylint: disable=line-too-long
	thread_two = threading.Thread(name="2", target=delete_product, args=({"id": "dummy-prod-1119", "product_version": "1.0", "package_version": "1"},config.internal_url)) # pylint: disable=line-too-long
	thread_three = threading.Thread(name="3", target=delete_product, args=({"id": "dummy-prod-1199", "product_version": "1.0", "package_version": "1"},config.internal_url)) # pylint: disable=line-too-long
	thread_four = threading.Thread(name="4", target=delete_product, args=({"id": "dummy-prod-2559", "product_version": "1.0", "package_version": "1"},config.internal_url)) # pylint: disable=line-too-long
	thread_five = threading.Thread(name="5", target=delete_product, args=({"id": "dummy-prod-1359", "product_version": "1.0", "package_version": "1"},config.internal_url)) # pylint: disable=line-too-long

	thread_one.start()
	thread_two.start()
	thread_three.start()
	thread_four.start()
	thread_five.start()

	thread_one.join()
	thread_two.join()
	thread_three.join()
	thread_four.join()
	thread_five.join()

	await asyncio.sleep(3)

	test_products_sorted.remove("dummy-prod-1039")
	test_products_sorted.remove("dummy-prod-1119")
	test_products_sorted.remove("dummy-prod-1199")
	test_products_sorted.remove("dummy-prod-2559")
	test_products_sorted.remove("dummy-prod-1359")

	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert decode_redis_result(cached_sorted_products) == test_products_sorted


@pytest.mark.asyncio
async def test_renew_cache(config, database_connection):  # pylint: disable=redefined-outer-name
	db_remove_dummy_products(database_connection)
	create_depot_rpc(config.internal_url, "testdepot.uib.gmbh")
	fill_db(database_connection)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	res.raise_for_status()
	result = res.json()

	test_products_sorted = read_sorted_products()
	assert result.get("result").get("sorted") == test_products_sorted

	await asyncio.sleep(3)

	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert decode_redis_result(cached_sorted_products) == test_products_sorted

	test_products = [
		{"id": "test_product01", "name": "Test Product 01", "product_version": "1.0", "package_version": "1", "priority": 80},
		{"id": "test_product02", "name": "Test Product 02", "product_version": "1.0", "package_version": "1", "priority": 81},
	]
	create_products(test_products, config.internal_url)



	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	res.raise_for_status()
	result = res.json()

	test_products_sorted.insert(0,"test_product01")
	test_products_sorted.insert(0,"test_product02")
	assert result.get("result").get("sorted") == test_products_sorted

	await asyncio.sleep(3)

	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert decode_redis_result(cached_sorted_products) == test_products_sorted

	db_remove_dummy_products(database_connection)
	delete_products(test_products, config.internal_url)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	res.raise_for_status()
	result = res.json()

	assert result.get("result").get("sorted") == []

	await asyncio.sleep(3)

	uptodate = await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:uptodate")
	uptodate_algorithm1= await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1:uptodate")

	assert uptodate is None
	assert uptodate_algorithm1 is None



@pytest.mark.asyncio
async def test_getProductOrdering(config, database_connection): # pylint: disable=invalid-name,redefined-outer-name

	db_remove_dummy_products(database_connection)

	test_products = [
		{"id": "test_product1", "name": "Test Product 1", "product_version": "1.0", "package_version": "1", "priority": 95},
		{"id": "test_product2", "name": "Test Product 2", "product_version": "1.0", "package_version": "1", "priority": 81},
		{"id": "test_product3", "name": "Test Product 3", "product_version": "1.0", "package_version": "1", "priority": 90}
	]
	test_products_sorted = ["test_product1", "test_product3", "test_product2"]

	create_depot_rpc(config.internal_url, "testdepot.uib.gmbh")
	create_products(test_products, config.internal_url)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	res.raise_for_status()
	result = res.json()

	num_results = len(result.get("result").get("sorted"))
	assert result.get("result").get("sorted") == test_products_sorted

	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert cached_sorted_products == []

	fill_db(database_connection)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	res.raise_for_status()
	result = res.json()

	test_products_sorted = read_sorted_products()
	test_products_sorted.insert(0, "test_product2")
	test_products_sorted.insert(0, "test_product3")
	test_products_sorted.insert(0, "test_product1")
	assert len(result.get("result").get("sorted")) > num_results
	assert result.get("result").get("sorted") == test_products_sorted

	await asyncio.sleep(3)

	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert cached_sorted_products[0].decode("utf8") == test_products_sorted[0]
	assert cached_sorted_products[1].decode("utf8") == test_products_sorted[1]
	assert cached_sorted_products[2].decode("utf8") == test_products_sorted[2]
	assert len(cached_sorted_products) == len(test_products_sorted)
	await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:uptodate")

	delete_products(test_products, config.internal_url)
	db_remove_dummy_products(database_connection)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	res.raise_for_status()
	result = res.json()

	assert len(result.get("result").get("sorted")) == 0


def read_sorted_products():
	sorted_products = []
	try:
		with open(os.path.join(os.path.dirname(__file__),'data/sorted_products.json'), encoding="utf-8") as file:
			sorted_products = file.read()
		sorted_products = json.loads(sorted_products)
	except Exception as err: # pylint: disable=broad-except
		print("Error while reading sorted_products")
		print(err)
	finally:
		return sorted_products # pylint: disable=lost-exception


def create_products(products, opsi_url):
	for product in products:

		params = [
			"localboot",
			product.get("id"),
			product.get("name"),
			product.get("product_version"),
			product.get("package_version"),
			None,None,None,None,None,None,
			product.get("priority"),
			None,None,None,None,None,None
			]
		rpc_request_data = json.dumps({"id": 1, "method": "createProduct", "params": params})
		res = requests.post(f"{opsi_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
		res.raise_for_status()


def create_dummy_products(n, opsi_url): # pylint: disable=invalid-name
	res = requests.get(opsi_url, auth=(ADMIN_USER, ADMIN_PASS), verify=False)
	res.raise_for_status()

	for i in range(0,n):
		params = [
			"localboot",
			f"dummy-prod-{i}",
			f"dummy PROD {i}",
			"1.0",
			"1",
			None,None,None,None,None,None,
			(i%80),
			None,None,None,None,None,None
			]
		rpc_request_data = json.dumps({"id": 1, "method": "createProduct", "params": params})
		res = requests.post(f"{opsi_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, cookies=res.cookies, verify=False)
		res.raise_for_status()


def delete_products(products, opsi_url):
	for product in products:
		params = [product.get("id"), product.get("product_version"), product.get("package_version")]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		res = requests.post(f"{opsi_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
		res.raise_for_status()


def delete_dummy_products(n, opsi_url): # pylint: disable=invalid-name
	res = requests.get(f"{opsi_url}/admin", auth=(ADMIN_USER, ADMIN_PASS), verify=False)
	res.raise_for_status()

	for i in range(0, n):
		params = [f"dummy-prod-{i}", "1.0", "1"]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		res = requests.post(f"{opsi_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, cookies=res.cookies, verify=False)
		res.raise_for_status()


def fill_db(database_connection):  # pylint: disable=redefined-outer-name
	cursor = database_connection.cursor()
	for num in range(8000):
		cursor.execute(
			'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) VALUES '
			f'("dummy-prod-{num}", "1.0", "1", "LocalbootProduct", "Dummy PRODUCT {num}", {num%80});'
		)
		cursor.execute(
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES '
			f'("dummy-prod-{num}", "1.0", "1", "testdepot.uib.gmbh", "LocalbootProduct");'
		)
	database_connection.commit()


def db_remove_dummy_products(database_connection):  # pylint: disable=redefined-outer-name
	cursor = database_connection.cursor()
	cursor.execute('DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "dummy-prod%";')
	cursor.execute('DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "test_product%";')

	cursor.execute('DELETE FROM PRODUCT WHERE productId like "dummy-prod%";')
	cursor.execute('DELETE FROM PRODUCT WHERE productId like "test_product%";')
	database_connection.commit()
