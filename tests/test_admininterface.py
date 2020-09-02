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

# from opsiconfd.config import config

from fastapi import Response
from starlette.requests import Request
from starlette.datastructures import Headers


OPSI_URL = "https://localhost:4447" 
TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"

def create_failed_requests():
	for i in range(0, 15):
		r = requests.get(OPSI_URL, auth=("false_user","false_pw"), verify=False)
		if i >= 12:
			assert r.status_code == 403
			assert r.text == "Client '127.0.0.1' is blocked for 2.00 minutes!"


def call_rpc(rpc_request_data: list, expect_error: list):
	for idx, data in enumerate(rpc_request_data):
		print(data)
		rpc_request_data = json.dumps(data)
		r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(r.text)
		assert r.status_code == 200
		if expect_error[idx]:
			assert result_json.get("result") == None
		else:
			assert result_json.get("result") != None
			assert result_json.get("error") == None
		assert result_json.get("method") == data.get("method")
	

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


def test_unblock_all_request():
	admin_request = requests.get(f"{OPSI_URL}/admin", auth=(TEST_USER, TEST_PW), verify=False)
	create_failed_requests()
	admin_request = requests.post(f"{OPSI_URL}/admin/unblock-all", auth=(TEST_USER, TEST_PW), cookies=admin_request.cookies, verify=False)
	assert admin_request.status_code == 200
	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200


def test_unblock_client_request():
	admin_request = requests.get(f"{OPSI_URL}/admin", auth=(TEST_USER, TEST_PW), verify=False)
	create_failed_requests()	
	admin_request = requests.post(f"{OPSI_URL}/admin/unblock-client", auth=(TEST_USER, TEST_PW), data="{\"client_addr\": \"127.0.0.1\"}", cookies=admin_request.cookies, verify=False)
	assert admin_request.status_code == 200

	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200


def test_get_rpc_list_request():
	for i in range(0, 3):
		call_rpc([{"id": 1, "method": "host_getIdents","params": [None]}], [False])

	r = requests.get(f"{OPSI_URL}/admin/rpc-list", auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	print(r.status_code)
	result = json.loads(r.text)
	print(result)
	for i in range(0,3):
		assert result[i].get("rpc_num") == i+1
		assert result[i].get("error") == False
		assert result[i].get("params") == "0"


def test_get_blocked_clients_request():
	admin_request = requests.get(f"{OPSI_URL}/admin", auth=(TEST_USER, TEST_PW), verify=False)
	create_failed_requests()
	admin_request = requests.get(f"{OPSI_URL}/admin/blocked-clients", auth=(TEST_USER, TEST_PW), cookies=admin_request.cookies, verify=False)
	assert admin_request.status_code == 200
	print(admin_request.text)
	assert admin_request.text ==  '["127.0.0.1"]'


get_rpc_count_test_data = [
	(0,0),
	(20,20),
	(3,3)
]
@pytest.mark.parametrize("num_rpcs, expexted_value", get_rpc_count_test_data)
@pytest.mark.asyncio
async def test_get_rpc_count(admininterface, num_rpcs, expexted_value):

	for i in range(0, num_rpcs):
		call_rpc([{"id": 1, "method": "host_getIdents","params": [None]}], [False])
	count = await admininterface.get_rpc_count()
	assert count == expexted_value


get_rpc_list_test_data = [1,3,5]
@pytest.mark.parametrize("num_rpcs", get_rpc_list_test_data)
@pytest.mark.asyncio
async def test_get_rpc_list(admininterface, num_rpcs):

	for i in range(0, num_rpcs):
		call_rpc([{"id": 1, "method": "host_getIdents","params": [None]}], [False])

	rpc_list = await admininterface.get_rpc_list()
	print(rpc_list)
	for i in range(0, num_rpcs):
		assert rpc_list[i].get("rpc_num") == i+1
		assert rpc_list[i].get("error") == False
		assert rpc_list[i].get("params") == "0"


@pytest.mark.asyncio
async def test_get_blocked_clients(admininterface):
	create_failed_requests()
	blocked_clients = await admininterface.get_blocked_clients()
	assert blocked_clients == ['127.0.0.1']


delete_client_test_data = [
		({"client_addr":"127.0.0.1"}, 0, [200, None, "127.0.0.1", 1]),
		({"client_addr":"192.168.2.1"}, 1, [200, None, "192.168.2.1", 0]),
		(None, 1, [500, {'detail': "'NoneType' object has no attribute 'get'", 'message': 'Error while removing redis client keys'}, None, 1])
	]
@pytest.mark.parametrize("rpc_request_data, expected_key_len, expected_response", delete_client_test_data)
@pytest.mark.asyncio
async def test_delete_client_sessions(admininterface, rpc_request_data, expected_key_len, expected_response):
	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	redis_client = aredis.StrictRedis.from_url("redis://redis")

	session = r.cookies.get_dict().get("opsiconfd-session")
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:127.0.0.1:*")
	keys = []
	async for key in session_keys:
		keys.append(key)
		print("!")
		print(key)
		assert key.decode("utf8") == f"{OPSI_SESSION_KEY}:127.0.0.1:{session}"

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
		if response_dict.get("status") == 200 and response_dict.get("data").get("client") == "127.0.0.1":
			assert response_dict.get("data").get("sessions") == [session]

		assert len(response_dict.get("data").get("redis-keys")) == expected_response[3]
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:127.0.0.1:*")
	keys = []
	async for key in session_keys:
		keys.append(key)
	assert len(keys) == expected_key_len


@pytest.mark.asyncio
async def test_unblock_all(admininterface):
	headers = Headers()
	scope = {
		'method': 'GET',
		'type': 'http',
		'headers': headers
	}
	test_request = Request(scope=scope)
	test_response = Response()
	
	create_failed_requests()

	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 403

	response = await admininterface.unblock_all_clients(test_request, test_response)
	print(response.__dict__)

	assert response.status_code == 200
	response_body =  json.loads(response.body)
	assert response_body.get("error") == None
	assert response_body.get("status") == 200
	assert len(response_body.get("data")) != 0 

	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	

@pytest.mark.asyncio
async def test_unblock_client(admininterface):

	create_failed_requests()

	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 403

	headers = Headers()
	scope = {
		'method': 'GET',
		'type': 'http',
		'headers': headers
	}
	test_request = Request(scope=scope)
	test_request._json = {"client_addr":"127.0.0.1"}
	body = '{"client_addr":"127.0.0.1"}'
	test_request._body = body.encode()

	print(test_request.json)
	response = await admininterface.unblock_client(test_request)
	response_dict = json.loads(response.body)
	assert response_dict.get("status") == 200
	assert response_dict.get("error") == None 

	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	

index_test_data = [
	(
		[
			{"id": 1, "method": "host_getIdents", "params": [None]},
			{"id": 2, "method": "host_getIdents", "params": [None]},
			{"id": 3, "method": "host_getIdents", "params": [None]}
		], 
		{
			"rpc_count": 3, 
			"method": ["host_getIdents", "host_getIdents", "host_getIdents"],
			"params": [0,0,0],
			"error": [False, False, False]
		},
	),
	(
		[
			{"id": 1, "method": "false_method", "params": [None]},
			{"id": 2, "method": "false_method", "params": ["test"]},
			{"id": 3, "method": "host_getIdents", "params": [None]}
		], 
		{
			"rpc_count": 3, 
			"method": ["false_method", "false_method", "host_getIdents"],
			"params": [0,1,0],
			"error": [True, True, False]
		},
	),
	(
		[
			{"id": 1, "method": "host_getObjects", "params": [["ipAddress","lastSeen"],{"ipAddress": "192.*"}]},
			{"id": 2, "method": "host_getObjects", "params": [["ipAddress"],{"ipAddress": "192.*"}]},
			{"id": 3, "method": "host_getObjects", "params": [[],{"ipAddress": "192.*"}]},
			{"id": 4, "method": "host_getObjects", "params": [["ipAddress"],{"ipAddress": "192.*","type": "OpsiClient"}]}
		], 
		{
			"rpc_count": 4, 
			"method": ["host_getObjects", "host_getObjects", "host_getObjects", "host_getObjects"],
			"params": [2,2,1,2],
			"error": [False, False, False, False]
		},
	)
]
@pytest.mark.parametrize("rpc_request_data, expected_response", index_test_data)
@pytest.mark.asyncio
async def test_admin_interface_index(admininterface, rpc_request_data, expected_response):

	call_rpc(rpc_request_data, expected_response.get("error"))
	create_failed_requests()

	headers = Headers()
	scope = {
			'method': 'GET',
			'type': 'http',
			'headers': headers
		}
	test_request = Request(scope=scope)
	response = await admininterface.admin_interface_index(test_request)

	assert response.context.get("rpc_count") == expected_response.get("rpc_count")


