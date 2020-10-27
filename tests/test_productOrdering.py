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
def test_getProductOrdering(request_data, expected_result):
	rpc_request_data = json.dumps(request_data)
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print(result_json)
	for host in result_json.get("result"):
		print(host.get("id"))
		print(host.get("type"))

	
