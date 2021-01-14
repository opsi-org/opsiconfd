# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""
import os
import sys
import json
import threading
import socket
import asyncio
import pytest
import urllib3
import aredis
import requests


from MySQLdb import _mysql
from opsiconfd.utils import decode_redis_result


TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)


@pytest.fixture
def fixture_config(monkeypatch, name="config"): # pylint: disable=unused-argument
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel
	return config


@pytest.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis(config):
	yield None
	print(config.redis_internal_url)
	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:*")
	async for key in session_keys:
		await redis_client.delete(key)
	await redis_client.delete(f"opsiconfd:stats:client:failed_auth:{LOCAL_IP}")
	await redis_client.delete(f"opsiconfd:stats:client:blocked:{LOCAL_IP}")
	client_keys = redis_client.scan_iter("opsiconfd:stats:client*")
	async for key in client_keys:
		print(key)
		await redis_client.delete(key)
	await redis_client.delete("opsiconfd:stats:rpcs")
	await redis_client.delete("opsiconfd:stats:num_rpcs")
	rpc_keys = redis_client.scan_iter("opsiconfd:stats:rpc:*")
	async for key in rpc_keys:
		print(key)
		await redis_client.delete(key)
	product_keys = redis_client.scan_iter("*products*")
	async for key in product_keys:
		print(key)
		await redis_client.delete(key)
	await asyncio.sleep(10)


@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def delete_product(product, opsi_url):
	print("delete: ", product)
	delete_products([product], opsi_url)
	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)
	print(result_json)


@pytest.mark.asyncio
async def test_delete_product(config):
	db_remove_dummy_products()
	create_depot(config.internal_url)
	fill_db()

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

	print(thread_one.is_alive())

	print("Threads running")

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
async def test_renew_cache(config):
	db_remove_dummy_products()
	create_depot(config.internal_url)
	fill_db()

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	test_products_sorted = read_sorted_products()
	assert result_json.get("result").get("sorted") == test_products_sorted

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
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	test_products_sorted.insert(0,"test_product01")
	test_products_sorted.insert(0,"test_product02")
	assert result_json.get("result").get("sorted") == test_products_sorted

	await asyncio.sleep(3)

	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert decode_redis_result(cached_sorted_products) == test_products_sorted

	db_remove_dummy_products()
	delete_products(test_products, config.internal_url)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	assert result_json.get("result").get("sorted") == []

	await asyncio.sleep(3)

	uptodate = await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:uptodate")
	uptodate_algorithm1= await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1:uptodate")

	assert uptodate is None
	assert uptodate_algorithm1 is None



@pytest.mark.asyncio
async def test_getProductOrdering(config): # pylint: disable=invalid-name

	db_remove_dummy_products()

	test_products = [
		{"id": "test_product1", "name": "Test Product 1", "product_version": "1.0", "package_version": "1", "priority": 95},
		{"id": "test_product2", "name": "Test Product 2", "product_version": "1.0", "package_version": "1", "priority": 81},
		{"id": "test_product3", "name": "Test Product 3", "product_version": "1.0", "package_version": "1", "priority": 90}
	]
	test_products_sorted = ["test_product1", "test_product3", "test_product2"]

	create_depot(config.internal_url)
	create_products(test_products, config.internal_url)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)
	print("1: ", result_json)

	num_results = len(result_json.get("result").get("sorted"))
	assert result_json.get("result").get("sorted") == test_products_sorted

	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert cached_sorted_products == []

	fill_db()

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	test_products_sorted = read_sorted_products()
	test_products_sorted.insert(0, "test_product2")
	test_products_sorted.insert(0, "test_product3")
	test_products_sorted.insert(0, "test_product1")
	assert len(result_json.get("result").get("sorted")) > num_results
	assert result_json.get("result").get("sorted") == test_products_sorted

	await asyncio.sleep(3)

	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	print(cached_sorted_products[0].decode("utf8"))
	print(test_products_sorted[0])
	assert cached_sorted_products[0].decode("utf8") == test_products_sorted[0]
	assert cached_sorted_products[1].decode("utf8") == test_products_sorted[1]
	assert cached_sorted_products[2].decode("utf8") == test_products_sorted[2]
	assert len(cached_sorted_products) == len(test_products_sorted)
	uptodate = await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:uptodate")
	print(uptodate)

	delete_products(test_products, config.internal_url)
	db_remove_dummy_products()

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)
	print(result_json)

	assert len(result_json.get("result").get("sorted")) == 0

def read_sorted_products():
	sorted_products = []
	try:
		with open(os.path.join(os.path.dirname(__file__),'data/sorted_products.json')) as file:
			sorted_products = file.read()
		sorted_products = json.loads(sorted_products)
	except Exception as err: # pylint: disable=broad-except
		print("Error while reading sorted_products")
		print(err)
	finally:
		return sorted_products # pylint: disable=lost-exception


def create_depot(opsi_url):
	params= ["testdepot.uib.gmbh",None,"file:///var/lib/opsi/depot","smb://172.17.0.101/opsi_depot",None,"file:///var/lib/opsi/repository","webdavs://172.17.0.101:4447/repository"] # pylint: disable=line-too-long

	rpc_request_data = json.dumps({"id": 1, "method": "host_createOpsiDepotserver", "params": params})
	res = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)
	print(result_json)

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
		res = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(res.text)
		print(result_json)

def create_dummy_products(n, opsi_url): # pylint: disable=invalid-name
	res = requests.get(opsi_url, auth=(TEST_USER, TEST_PW), verify=False)

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
		print(f"dummy-prod-{i}")
		print(f"PRIO: {(i%80)}")
		rpc_request_data = json.dumps({"id": 1, "method": "createProduct", "params": params})
		res = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, cookies=res.cookies, verify=False)
		result_json = json.loads(res.text)
		print(result_json)

def delete_products(products, opsi_url):
	for product in products:
		params = [product.get("id"), product.get("product_version"), product.get("package_version")]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		res = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(res.text)
		print(result_json)

def delete_dummy_products(n, opsi_url): # pylint: disable=invalid-name
	res = requests.get(f"{opsi_url}/admin", auth=(TEST_USER, TEST_PW), verify=False)

	for i in range(0, n):
		params = [f"dummy-prod-{i}", "1.0", "1"]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		res = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, cookies=res.cookies, verify=False)
		# result_json = json.loads(r.text)
		# print(result_json)
	print(f"deleted {n} dummy products")

def fill_db():
	n = 8000 # pylint: disable=invalid-name
	for i in range(0, n):
		mysql_host = os.environ.get("MYSQL_HOST")
		if not mysql_host:
			mysql_host = "127.0.0.1"
		db=_mysql.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi") # pylint: disable=invalid-name, c-extension-no-member
		sql_string = f'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) VALUES ("dummy-prod-{i}", "1.0", "1", "LocalbootProduct", "Dummy PRODUCT {i}", {i%80});'  # pylint: disable=line-too-long
		# print(sql_string)
		db.query(sql_string)
		sql_string = f'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES ("dummy-prod-{i}", "1.0", "1", "testdepot.uib.gmbh", "LocalbootProduct");' # pylint: disable=line-too-long
		db.query(sql_string)
		db.query(f'SELECT * FROM PRODUCT WHERE productId like "dummy-prod-{i}";')
		db.store_result()
		# print(r.fetch_row(maxrows=0))

def db_remove_dummy_products():
	mysql_host = os.environ.get("MYSQL_HOST")
	if not mysql_host:
		mysql_host = "127.0.0.1"
	db = _mysql.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi") # pylint: disable=invalid-name, c-extension-no-member
	db.query('DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "dummy-prod%";')
	db.query('DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "test_product%";')

	db.query('DELETE FROM PRODUCT WHERE productId like "dummy-prod%";')
	db.query('DELETE FROM PRODUCT WHERE productId like "test_product%";')
	db.store_result()
