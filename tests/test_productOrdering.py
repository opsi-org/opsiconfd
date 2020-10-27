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


def test_getProductOrdering():

	test_products = [
		{"id": "test_product1", "name": "Test Product 1", "product_version": "1.0", "package_version": "1", "priority": 95}, 
		{"id": "test_product2", "name": "Test Product 2", "product_version": "1.0", "package_version": "1", "priority": 80}, 
		{"id": "test_product3", "name": "Test Product 3", "product_version": "1.0", "package_version": "1", "priority": 90}
	]

	create_depot()

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)
	print(result_json)

	num_results = len(result_json.get("result").get("sorted"))

	redis_client = redis.StrictRedis.from_url("redis://redis")
	products = redis_client.zrange("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products", 0, -1)
	print(products)
	uptodate = redis_client.get("opsiconfd:jsonrpccache:testdepot.uib.gmbh:products:uptodate")
	print(uptodate)

	create_products(test_products)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)
	print(result_json)

	assert len(result_json.get("result").get("sorted")) > num_results

	delete_products(test_products)

	rpc_request_data = json.dumps({"id": 1, "method": "getProductOrdering", "params": ["testdepot.uib.gmbh", "algorithm1"]})
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)
	print(result_json)

	assert len(result_json.get("result").get("sorted")) == num_results

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

def delete_products(products):
	
	for product in products:
		params = [product.get("id"), product.get("product_version"), product.get("package_version")]
		rpc_request_data = json.dumps({"id": 1, "method": "product_delete", "params": params})
		r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(r.text)
		print(result_json)