import os
import sys
import pytest
import asyncio
import time
import urllib3
import aredis
import requests
import json
import threading
import socket 

from MySQLdb import _mysql
from opsiconfd.utils import decode_redis_result


TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)


@pytest.fixture
def config(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config
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
	r = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)


@pytest.mark.asyncio
async def test_delete_product(config):
	db_remove_dummy_products()
	create_depot(config.internal_url)
	fill_db()

	test_products_sorted = read_sorted_products()
	
	thread_one = threading.Thread(name="1", target=delete_product, args=({"id": "dummy-prod-1039", "product_version": "1.0", "package_version": "1"},config.internal_url)) 
	thread_two = threading.Thread(name="2", target=delete_product, args=({"id": "dummy-prod-1119", "product_version": "1.0", "package_version": "1"},config.internal_url)) 
	thread_three = threading.Thread(name="3", target=delete_product, args=({"id": "dummy-prod-1199", "product_version": "1.0", "package_version": "1"},config.internal_url)) 
	thread_four = threading.Thread(name="4", target=delete_product, args=({"id": "dummy-prod-2559", "product_version": "1.0", "package_version": "1"},config.internal_url)) 
	thread_five = threading.Thread(name="5", target=delete_product, args=({"id": "dummy-prod-1359", "product_version": "1.0", "package_version": "1"},config.internal_url)) 

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
	r = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

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
	r = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	test_products_sorted.insert(0,"test_product01")
	test_products_sorted.insert(0,"test_product02")
	assert result_json.get("result").get("sorted") == test_products_sorted

	await asyncio.sleep(3)
	
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert decode_redis_result(cached_sorted_products) == test_products_sorted

	db_remove_dummy_products()
	delete_products(test_products, config.internal_url)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	assert result_json.get("result").get("sorted") == []

	await asyncio.sleep(3)

	uptodate = await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:uptodate")
	uptodate_algorithm1= await redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1:uptodate")

	assert uptodate == None
	assert uptodate_algorithm1 == None



@pytest.mark.asyncio
async def test_getProductOrdering(config):
	
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
	r = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)
	print("1: ", result_json)

	num_results = len(result_json.get("result").get("sorted"))
	assert result_json.get("result").get("sorted") == test_products_sorted

	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)
	cached_sorted_products = await redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:algorithm1", 0, -1)
	assert cached_sorted_products == []

	fill_db()

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

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
	r = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
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
	

def create_depot(opsi_url):
	params= ["testdepot.uib.gmbh",None,"file:///var/lib/opsi/depot","smb://172.17.0.101/opsi_depot",None,"file:///var/lib/opsi/repository","webdavs://172.17.0.101:4447/repository"]

	rpc_request_data = json.dumps({"id": 1, "method": "host_createOpsiDepotserver", "params": params})
	r = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)
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
		r = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(r.text)
		print(result_json)
	
def create_dummy_products(n, opsi_url):
	r = requests.get(opsi_url, auth=(TEST_USER, TEST_PW), verify=False)
	
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
		r = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, cookies=r.cookies, verify=False)
		result_json = json.loads(r.text)

def delete_products(products, opsi_url):	
	for product in products:
		params = [product.get("id"), product.get("product_version"), product.get("package_version")]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		r = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(r.text)
		print(result_json)

def delete_dummy_products(n, opsi_url):
	r = requests.get(f"{opsi_url}/admin", auth=(TEST_USER, TEST_PW), verify=False)
	
	for i in range(0, n):
		params = [f"dummy-prod-{i}", "1.0", "1"]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		r = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, cookies=r.cookies, verify=False)
		# result_json = json.loads(r.text)
		# print(result_json)
	print(f"deleted {n} dummy products")

def fill_db():
	n = 8000
	for i in range(0, n):
		mysql_host = os.environ.get("MYSQL_HOST")
		if not mysql_host:
			mysql_host = "127.0.0.1"
		db=_mysql.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi")
		sql_string = f'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) VALUES ("dummy-prod-{i}", "1.0", "1", "LocalbootProduct", "Dummy PRODUCT {i}", {i%80});'
		# print(sql_string)
		db.query(sql_string)
		sql_string = f'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES ("dummy-prod-{i}", "1.0", "1", "testdepot.uib.gmbh", "LocalbootProduct");'
		db.query(sql_string)
		db.query(f'SELECT * FROM PRODUCT WHERE productId like "dummy-prod-{i}";')
		r=db.store_result()
		# print(r.fetch_row(maxrows=0))

def db_remove_dummy_products():
	mysql_host = os.environ.get("MYSQL_HOST")
	if not mysql_host:
		mysql_host = "127.0.0.1"
	db = _mysql.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi")
	db.query(f'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "dummy-prod%";')
	db.query(f'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "test_product%";')
	
	db.query(f'DELETE FROM PRODUCT WHERE productId like "dummy-prod%";')
	db.query(f'DELETE FROM PRODUCT WHERE productId like "test_product%";')
	db.store_result()