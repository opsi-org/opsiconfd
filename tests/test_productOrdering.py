import os
import sys
import pytest
import asyncio
import time
import urllib3
import redis
import aredis
import requests
import json

from MySQLdb import _mysql
from opsiconfd.utils import decode_redis_result

OPSI_URL = "https://localhost:4447" 
TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"

@pytest.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis():
	yield None
	redis_client = aredis.StrictRedis.from_url("redis://redis")
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:127.0.0.1:*")
	async for key in session_keys:
		await redis_client.delete(key)
	await redis_client.delete("opsiconfd:stats:client:failed_auth:127.0.0.1")
	await redis_client.delete("opsiconfd:stats:client:blocked:127.0.0.1")
	session_keys = redis_client.scan_iter("opsiconfd:stats:rpc:*")
	async for key in session_keys:
		print(key)
		await redis_client.delete(key)
	await redis_client.delete("opsiconfd:stats:num_rpcs")
	product_keys = redis_client.scan_iter("*products*")
	async for key in product_keys:
		print(key)
		await redis_client.delete(key)

@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



jsonrpc_test_data = [
	(
		{"id": 1, "method": "host_getObjects", "params": []},
		{
			"num_results": 3, 
			"status_code": 200, 
			"method": "host_getObjects", 
			"id": "pytest2.uib.gmbh", 
			"ipAddress": "192.168.0.111", 
			"notes": None, 
			"type": "OpsiClient",
			"error": None
		}
	)

]

@pytest.mark.parametrize("request_data, expected_result", jsonrpc_test_data)
def test_getHosts(request_data, expected_result):
	rpc_request_data = json.dumps(request_data)
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print(result_json)
	for host in result_json.get("result"):
		print(host.get("id"))
		print(host.get("type"))

@pytest.mark.asyncio
async def test_renew_cache():
	db_remove_dummy_products()
	create_depot()
	fill_db()

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	test_product_sorted = read_sorted_products()
	assert result_json.get("result").get("sorted") == test_product_sorted

	print("wait 3s")
	await asyncio.sleep(3)
	print("READ REDIS CACHE")

	redis_client = aredis.StrictRedis.from_url("redis://redis")
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert decode_redis_result(cached_sorted_products) == test_product_sorted

	test_products = [
		{"id": "test_product01", "name": "Test Product 01", "product_version": "1.0", "package_version": "1", "priority": 80}, 
		{"id": "test_product02", "name": "Test Product 02", "product_version": "1.0", "package_version": "1", "priority": 81}, 
	]
	create_products(test_products)

	

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	test_product_sorted.insert(0,"test_product01")
	test_product_sorted.insert(0,"test_product02")
	assert result_json.get("result").get("sorted") == test_product_sorted

	print("wait 3s")
	await asyncio.sleep(3)
	print("READ REDIS CACHE")

	redis_client = aredis.StrictRedis.from_url("redis://redis")
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert decode_redis_result(cached_sorted_products) == test_product_sorted

	db_remove_dummy_products()


@pytest.mark.asyncio
async def test_getProductOrdering():
	
	db_remove_dummy_products()

	test_products = [
		{"id": "test_product1", "name": "Test Product 1", "product_version": "1.0", "package_version": "1", "priority": 95}, 
		{"id": "test_product2", "name": "Test Product 2", "product_version": "1.0", "package_version": "1", "priority": 81}, 
		{"id": "test_product3", "name": "Test Product 3", "product_version": "1.0", "package_version": "1", "priority": 90}
	]
	test_product_sorted = ["test_product1", "test_product3", "test_product2"]

	create_depot()
	create_products(test_products)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)
	print("1: ", result_json)

	num_results = len(result_json.get("result").get("sorted"))
	assert result_json.get("result").get("sorted") == test_product_sorted

	redis_client = aredis.StrictRedis.from_url("redis://redis")
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert cached_sorted_products == []
	uptodate = await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:uptodate")
	print(uptodate)


	fill_db()

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	
	test_product_sorted = read_sorted_products()
	test_product_sorted.insert(0, "test_product2")
	test_product_sorted.insert(0, "test_product3")
	test_product_sorted.insert(0, "test_product1")
	assert len(result_json.get("result").get("sorted")) > num_results
	assert result_json.get("result").get("sorted") == test_product_sorted

	print("READ REDIS CACHE")

	await asyncio.sleep(3)

	redis_client = aredis.StrictRedis.from_url("redis://redis")
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	print(cached_sorted_products[0].decode("utf8"))
	print(test_product_sorted[0])
	assert cached_sorted_products[0].decode("utf8") == test_product_sorted[0]
	assert cached_sorted_products[1].decode("utf8") == test_product_sorted[1]
	assert cached_sorted_products[2].decode("utf8") == test_product_sorted[2]
	assert len(cached_sorted_products) == len(test_product_sorted)
	uptodate = await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:uptodate")
	print(uptodate)

	delete_products(test_products)
	db_remove_dummy_products()
	

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)
	print(result_json)

	assert len(result_json.get("result").get("sorted")) == 0

def read_sorted_products():
	sorted_products = []
	try:
		with open(os.path.join(os.path.dirname(__file__),'data/sorted_products.json')) as file:
			sorted_products = file.read()
		sorted_products = json.loads(sorted_products)
	except:
		print("Error while reading sorted_products")
	finally:
		return sorted_products
	

def create_depot():

	params= ["testdepot.uib.gmbh",None,"file:///var/lib/opsi/depot","smb://172.17.0.101/opsi_depot",None,"file:///var/lib/opsi/repository","webdavs://172.17.0.101:4447/repository"]


	rpc_request_data = json.dumps({"id": 1, "method": "host_createOpsiDepotserver", "params": params})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)
	print(result_json)

def create_products(products):

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
		r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(r.text)
		print(result_json)
	
def create_dummy_products(n):
	r = requests.get("https://localhost:4447/admin", auth=(TEST_USER, TEST_PW), verify=False)
	
	
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
		r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, cookies=r.cookies, verify=False)
		result_json = json.loads(r.text)
		# print(result_json)


def delete_products(products):
	
	for product in products:
		params = [product.get("id"), product.get("product_version"), product.get("package_version")]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(r.text)
		print(result_json)

def delete_dummy_products(n):
	r = requests.get("https://localhost:4447/admin", auth=(TEST_USER, TEST_PW), verify=False)
	
	for i in range(0, n):
		params = [f"dummy-prod-{i}", "1.0", "1"]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, cookies=r.cookies, verify=False)
		result_json = json.loads(r.text)
		# print(result_json)
	print(f"deleted {n} dummy products")

def fill_db():

	n = 8000
	for i in range(0, n):

		db=_mysql.connect(host="mysql",user="opsi",passwd="opsi",db="opsi")
		sql_string = f'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) VALUES ("dummy-prod-{i}", "1.0", "1", "LocalbootProduct", "Dummy PRODUCT {i}", {i%80});'
		# print(sql_string)
		db.query(sql_string)
		sql_string = f'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES ("dummy-prod-{i}", "1.0", "1", "testdepot.uib.gmbh", "LocalbootProduct");'
		db.query(sql_string)
		db.query(f'SELECT * FROM PRODUCT WHERE productId like "dummy-prod-{i}";')
		r=db.store_result()
		# print(r.fetch_row(maxrows=0))

def db_remove_dummy_products():
	db = _mysql.connect(host="mysql",user="opsi",passwd="opsi",db="opsi")
	db.query(f'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "dummy-prod%";')
	db.query(f'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "test_product%";')
	
	db.query(f'DELETE FROM PRODUCT WHERE productId like "dummy-prod%";')
	db.query(f'DELETE FROM PRODUCT WHERE productId like "test_product%";')
	db.store_result()