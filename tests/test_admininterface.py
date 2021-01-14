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

import sys
import asyncio
import time
import json
import socket
import pytest
import aredis
import urllib3
import requests

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
	await redis_client.execute_command(f"ts.create opsiconfd:stats:client:failed_auth:{LOCAL_IP} RETENTION 86400000 LABELS client_addr {LOCAL_IP}") # pylint: disable=line-too-long

	await redis_client.execute_command(f"ts.add opsiconfd:stats:client:failed_auth:{LOCAL_IP} * 11 RETENTION 86400000 LABELS client_addr {LOCAL_IP}") # pylint: disable=line-too-long
	await redis_client.set(f"opsiconfd:stats:client:blocked:{LOCAL_IP}", True)
	result = requests.get(opsi_url, auth=(TEST_USER, TEST_PW), verify=False)
	print(result.__dict__)
	assert result.status_code == 403
	assert result.text == f"Client '{LOCAL_IP}' is blocked"


def call_rpc(rpc_request_data: list, expect_error: list, url):
	for idx, data in enumerate(rpc_request_data):
		print(data)
		rpc_request_data = json.dumps(data)
		result = requests.post(f"{url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
		result_json = json.loads(result.text)
		assert result.status_code == 200
		if expect_error[idx]:
			assert result_json.get("result") is None
		else:
			assert result_json.get("result") is not None
			assert result_json.get("error") is None


@pytest.fixture(name="adminiterface")
def fixture_admininterface(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.application import admininterface # pylint: disable=import-outside-toplevel, redefined-outer-name
	return admininterface


@pytest.fixture( name="config")
def fixture_config(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel, redefined-outer-name
	return config


@pytest.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis(config): # pylint: disable=redefined-outer-name
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
	admin_request = requests.post(f"{config.internal_url}/admin/unblock-all", auth=(TEST_USER, TEST_PW), cookies=admin_request.cookies, verify=False) # pylint: disable=line-too-long
	assert admin_request.status_code == 200
	result = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert result.status_code == 200

@pytest.mark.asyncio
async def test_unblock_client_request(config):

	admin_request = requests.get(f"{config.internal_url}/admin", auth=(TEST_USER, TEST_PW), verify=False)
	await create_failed_requests(config.internal_url, config.redis_internal_url)
	admin_request = requests.post(f"{config.internal_url}/admin/unblock-client", auth=(TEST_USER, TEST_PW), data=f'{{"client_addr": "{LOCAL_IP}"}}', cookies=admin_request.cookies, verify=False) # pylint: disable=line-too-long
	assert admin_request.status_code == 200

	result = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert result.status_code == 200

def test_get_rpc_list_request(config):
	for i in range(0, 3):
		call_rpc([{"id": 1, "method": "host_getIdents","params": [None]}], [False], config.internal_url)
	time.sleep(5)

	response = requests.get(f"{config.internal_url}/admin/rpc-list", auth=(TEST_USER, TEST_PW), verify=False)
	assert response.status_code == 200
	print(response.status_code)
	result = json.loads(response.text)
	print(result)
	for i in range(0,3):
		assert result[i].get("rpc_num") == i+1
		assert result[i].get("error") is False
		assert result[i].get("params") == 0

@pytest.mark.asyncio
async def test_get_blocked_clients_request(config): # pylint: disable=redefined-outer-name
	admin_request = requests.get(f"{config.internal_url}/admin", auth=(TEST_USER, TEST_PW), verify=False)
	await create_failed_requests(config.internal_url, config.redis_internal_url)
	admin_request = requests.get(f"{config.internal_url}/admin/blocked-clients", auth=(TEST_USER, TEST_PW), cookies=admin_request.cookies, verify=False) # pylint: disable=line-too-long
	assert admin_request.status_code == 200
	print(admin_request.text)
	assert admin_request.text ==  f'["{LOCAL_IP}"]'


get_rpc_list_test_data = [1,3,5]
@pytest.mark.parametrize("num_rpcs", get_rpc_list_test_data)
@pytest.mark.asyncio
async def test_get_rpc_list(config, admininterface, num_rpcs): # pylint: disable=redefined-outer-name

	for i in range(0, num_rpcs):
		call_rpc([{"id": 1, "method": "host_getIdents","params": [None]}], [False], config.internal_url)
	await asyncio.sleep(5)
	rpc_list = await admininterface.get_rpc_list()
	print(rpc_list)
	for i in range(0, num_rpcs):
		assert rpc_list[i].get("rpc_num") == i+1
		assert rpc_list[i].get("error") is False
		assert rpc_list[i].get("params") == 0


@pytest.mark.asyncio
async def test_get_blocked_clients(admininterface, config): # pylint: disable=redefined-outer-name

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
async def test_delete_client_sessions(config, admininterface, rpc_request_data, expected_key_len, expected_response): # pylint: disable=redefined-outer-name, too-many-locals
	res = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert res.status_code == 200
	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)

	session = res.cookies.get_dict().get("opsiconfd-session")
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
	test_request._json = rpc_request_data # pylint: disable=protected-access
	body = f'{rpc_request_data}'
	test_request._body = body.encode() # pylint: disable=protected-access
	print(test_request.json)

	response = await admininterface.delete_client_sessions(test_request)
	print(response.__dict__)

	response_dict = json.loads(response.body)
	assert response_dict.get("status") == expected_response[0]
	assert response_dict.get("error") == expected_response[1]

	if response_dict.get("error") is None:
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
	test_response = Response()

	await create_failed_requests(config.internal_url, config.redis_internal_url)

	res = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert res.status_code == 403

	response = await admininterface.unblock_all_clients(test_response)
	print(response.__dict__)

	assert response.status_code == 200
	response_body =  json.loads(response.body)
	assert response_body.get("error") is None
	assert response_body.get("status") == 200
	assert len(response_body.get("data")) != 0

	res = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert res.status_code == 200


@pytest.mark.asyncio
async def test_unblock_client(config, admininterface):

	await create_failed_requests(config.internal_url, config.redis_internal_url)

	res = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert res.status_code == 403

	headers = Headers()
	scope = {
		'method': 'GET',
		'type': 'http',
		'headers': headers
	}
	test_request = Request(scope=scope)
	test_request._json = {"client_addr":LOCAL_IP} # pylint: disable=protected-access
	body = f'{{"client_addr":"{config.internal_url}"}}'
	test_request._body = body.encode() # pylint: disable=protected-access

	print(test_request.json)
	response = await admininterface.unblock_client(test_request)
	response_dict = json.loads(response.body)
	assert response_dict.get("status") == 200
	assert response_dict.get("error") is None

	res = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert res.status_code == 200



# TODO test number of keys in rpc list
