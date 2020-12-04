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
import re
import socket
# from opsiconfd.config import config

from fastapi import Response
from starlette.requests import Request
from starlette.datastructures import Headers



TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)

async def create_failed_requests(opsi_url, redis_url):

	print("IP: ", LOCAL_IP)

	redis_client = aredis.StrictRedis.from_url(redis_url)
	await redis_client.execute_command(f"ts.create opsiconfd:stats:client:failed_auth:{LOCAL_IP} RETENTION 86400000 LABELS client_addr {LOCAL_IP}")

	await redis_client.execute_command(f"ts.add opsiconfd:stats:client:failed_auth:{LOCAL_IP} * 11 RETENTION 86400000 LABELS client_addr {LOCAL_IP}")
	await redis_client.set(f"opsiconfd:stats:client:blocked:{LOCAL_IP}", True)
	r = requests.get(opsi_url, auth=(TEST_USER, TEST_PW), verify=False)
	print(r.__dict__)
	assert r.status_code == 403
	assert r.text == f"Client '{LOCAL_IP}' is blocked"


def call_rpc(rpc_request_data: list, expect_error: list, url):
	for idx, data in enumerate(rpc_request_data):
		print(data)
		rpc_request_data = json.dumps(data)
		r = requests.post(f"{url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(r.text)
		assert r.status_code == 200
		if expect_error[idx]:
			assert result_json.get("result") == None
		else:
			assert result_json.get("result") != None
			assert result_json.get("error") == None
	

@pytest.fixture
def admininterface(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.application import admininterface
	return admininterface


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
	print(f"opsiconfd:stats:client:failed_auth:{LOCAL_IP}")
	print(f"opsiconfd:stats:client:blocked:{LOCAL_IP}")
	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:*")
	async for key in session_keys:
		print(key)
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
	await asyncio.sleep(10)

@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@pytest.mark.asyncio
async def test_unblock_all_request(config):
	print(config.port)
	print(config.external_url)
	print(config.internal_url)
	admin_request = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	await create_failed_requests(config.internal_url, config.redis_internal_url)
	admin_request = requests.post(f"{config.internal_url}/admin/unblock-all", auth=(TEST_USER, TEST_PW), cookies=admin_request.cookies, verify=False)
	assert admin_request.status_code == 200
	r = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200

@pytest.mark.asyncio
async def test_unblock_client_request(config):

	admin_request = requests.get(f"{config.internal_url}/admin", auth=(TEST_USER, TEST_PW), verify=False)
	await create_failed_requests(config.internal_url, config.redis_internal_url)	
	admin_request = requests.post(f"{config.internal_url}/admin/unblock-client", auth=(TEST_USER, TEST_PW), data=f'{{"client_addr": "{LOCAL_IP}"}}', cookies=admin_request.cookies, verify=False)
	assert admin_request.status_code == 200

	r = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200

def test_get_rpc_list_request(config):
	for i in range(0, 3):
		call_rpc([{"id": 1, "method": "host_getIdents","params": [None]}], [False], config.internal_url)
	time.sleep(5)

	r = requests.get(f"{config.internal_url}/admin/rpc-list", auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	print(r.status_code)
	result = json.loads(r.text)
	print(result)
	for i in range(0,3):
		assert result[i].get("rpc_num") == i+1
		assert result[i].get("error") == False
		assert result[i].get("params") == 0

@pytest.mark.asyncio
async def test_get_blocked_clients_request(config):
	admin_request = requests.get(f"{config.internal_url}/admin", auth=(TEST_USER, TEST_PW), verify=False)
	await create_failed_requests(config.internal_url, config.redis_internal_url)
	admin_request = requests.get(f"{config.internal_url}/admin/blocked-clients", auth=(TEST_USER, TEST_PW), cookies=admin_request.cookies, verify=False)
	assert admin_request.status_code == 200
	print(admin_request.text)
	assert admin_request.text ==  f'["{LOCAL_IP}"]'


get_rpc_list_test_data = [1,3,5]
@pytest.mark.parametrize("num_rpcs", get_rpc_list_test_data)
@pytest.mark.asyncio
async def test_get_rpc_list(config, admininterface, num_rpcs):

	for i in range(0, num_rpcs):
		call_rpc([{"id": 1, "method": "host_getIdents","params": [None]}], [False], config.internal_url)
	await asyncio.sleep(5)
	rpc_list = await admininterface.get_rpc_list()
	print(rpc_list)
	for i in range(0, num_rpcs):
		assert rpc_list[i].get("rpc_num") == i+1
		assert rpc_list[i].get("error") == False
		assert rpc_list[i].get("params") == 0


@pytest.mark.asyncio
async def test_get_blocked_clients(admininterface, config):

	await create_failed_requests(config.internal_url, config.redis_internal_url)
	blocked_clients = await admininterface.get_blocked_clients()
	assert blocked_clients == [LOCAL_IP]


delete_client_test_data = [
		({"client_addr":LOCAL_IP}, 0, [200, None, LOCAL_IP, 1]),
		({"client_addr":"192.168.2.1"}, 1, [200, None, "192.168.2.1", 0]),
		(None, 1, [500, {'detail': "'NoneType' object has no attribute 'get'", 'message': 'Error while removing redis client keys'}, None, 1])
	]
@pytest.mark.parametrize("rpc_request_data, expected_key_len, expected_response", delete_client_test_data)
@pytest.mark.asyncio
async def test_delete_client_sessions(config, admininterface, rpc_request_data, expected_key_len, expected_response):
	r = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)

	session = r.cookies.get_dict().get("opsiconfd-session")
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:{LOCAL_IP}:*")
	keys = []
	async for key in session_keys:
		keys.append(key)
		print("!")
		print(key)
		assert key.decode("utf8") == f"{OPSI_SESSION_KEY}:{LOCAL_IP}:{session}"

	assert len(keys) != 0
	print(len(keys))

	headers = Headers()
	scope = {
		'method': 'GET',
		'type': 'http',
		'headers': headers
	}
	test_request = Request(scope=scope)
	print(test_request)
	test_request._json = rpc_request_data
	body = f'{rpc_request_data}'
	test_request._body = body.encode()
	print(test_request.json)

	response = await admininterface.delete_client_sessions(test_request)
	print(response.__dict__)

	response_dict = json.loads(response.body)
	assert response_dict.get("status") == expected_response[0]
	assert response_dict.get("error") == expected_response[1]

	if response_dict.get("error") == None:
		assert response_dict.get("data").get("client") == expected_response[2]
		if response_dict.get("status") == 200 and response_dict.get("data").get("client") == LOCAL_IP:
			assert response_dict.get("data").get("sessions") == [session]

		assert len(response_dict.get("data").get("redis-keys")) == expected_response[3]
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:{LOCAL_IP}:*")
	keys = []
	async for key in session_keys:
		keys.append(key)
	assert len(keys) == expected_key_len


@pytest.mark.asyncio
async def test_unblock_all(config, admininterface):
	headers = Headers()
	scope = {
		'method': 'GET',
		'type': 'http',
		'headers': headers
	}
	test_request = Request(scope=scope)
	test_response = Response()
	
	await create_failed_requests(config.internal_url, config.redis_internal_url)

	r = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 403

	response = await admininterface.unblock_all_clients(test_request, test_response)
	print(response.__dict__)

	assert response.status_code == 200
	response_body =  json.loads(response.body)
	assert response_body.get("error") == None
	assert response_body.get("status") == 200
	assert len(response_body.get("data")) != 0 

	r = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	

@pytest.mark.asyncio
async def test_unblock_client(config, admininterface):

	await create_failed_requests(config.internal_url, config.redis_internal_url)

	r = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 403

	headers = Headers()
	scope = {
		'method': 'GET',
		'type': 'http',
		'headers': headers
	}
	test_request = Request(scope=scope)
	test_request._json = {"client_addr":LOCAL_IP}
	body = f'{{"client_addr":"{config.internal_url}"}}'
	test_request._body = body.encode()

	print(test_request.json)
	response = await admininterface.unblock_client(test_request)
	response_dict = json.loads(response.body)
	assert response_dict.get("status") == 200
	assert response_dict.get("error") == None 

	r = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	


# TODO test number of keys in rpc list
