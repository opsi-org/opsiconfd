
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
import socket
import json
import asyncio
import urllib3
import aredis
import requests
import pytest



from MySQLdb import _mysql

OPSI_URL = "https://localhost:4447"
TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)

@pytest.fixture(name="config")
def fixture_config(monkeypatch): # pylint: disable=unused-argument
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel
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

@pytest.fixture(name="fill_db")
def fixture_fill_db(): # pylint: disable=unused-argument
	mysql_data = [
		{
			"hostId": "pytest.uib.gmbh",
			"type": "OpsiClient",
			"description": "pytest test data description",
			"notes": "pytest test data notes",
			"hardwareAddress": "32:58:fd:f7:3b:26",
			"ipAddress": "192.168.0.12",
			"inventoryNumber": "0815",
			"created": "2017-11-14 14:43:48",
			"lastSeen": "2017-11-14 14:43:48"

		},
		{
			"hostId": "pytest2.uib.gmbh",
			"type": "OpsiClient",
			"description": "pytest test data description",
			"notes": "pytest test data notes",
			"hardwareAddress": "32:58:fd:f7:3b:26",
			"ipAddress": "192.168.0.111",
			"inventoryNumber": "0815",
			"created": "2017-11-14 14:43:48",
			"lastSeen": "2017-11-14 14:43:48"

		},
		{
			"hostId": "pytest3.uib.gmbh",
			"type": "OpsiClient",
			"description": "pytest test data description",
			"notes": "pytest test data notes",
			"hardwareAddress": "32:58:fd:f7:3b:26",
			"ipAddress": "192.168.0.111",
			"inventoryNumber": "0815",
			"created": "2017-11-14 14:43:48",
			"lastSeen": "2017-11-14 14:43:48"

		},
		{
			"hostId": "pytest4.uib.gmbh",
			"type": "OpsiClient",
			"description": "pytest test data description",
			"notes": "pytest test data notes",
			"hardwareAddress": "32:58:fd:f7:3b:26",
			"ipAddress": "192.168.0.111",
			"inventoryNumber": "0815",
			"created": "2017-11-14 14:43:48",
			"lastSeen": "2017-11-14 14:43:48"

		}
	]

	# TODO assert mysql results
	# TODO insert more Data
	db = None # pylint: disable=invalid-name
	for data in mysql_data:
		mysql_host = os.environ.get("MYSQL_HOST")
		if not mysql_host:
			mysql_host = "127.0.0.1"
		db=_mysql.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi") # pylint: disable=invalid-name, c-extension-no-member
		sql_string = f'INSERT INTO HOST (hostId, type, description, notes,  hardwareAddress, ipAddress, inventoryNumber, created, lastSeen) VALUES (\"{data["hostId"]}\", \"{data["type"]}\", \"{data["description"]}\", \"{data["notes"]}\", \"{data["hardwareAddress"]}\", \"{data["ipAddress"]}\", \"{data["inventoryNumber"]}\", \"{data["created"]}\",  \"{data["lastSeen"]}\");' # pylint: disable=line-too-long
		print(sql_string)
		db.query(sql_string)
		db.query(f'SELECT * FROM HOST WHERE ipAddress like \"{data["ipAddress"]}\";')
		res=db.store_result()
		print(res.fetch_row(maxrows=0))

	yield None

	for data in mysql_data:
		db.query(f'DELETE FROM HOST WHERE ipAddress like \"{data["ipAddress"]}\";')




jsonrpc_test_data = [
	(
		{"id": 1, "method": "host_getObjects", "params": [["ipAddress","id","notes"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": "192.168.0.12",
			"notes": "pytest test data notes",
			"type": "OpsiClient",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [["ipAddress"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": "192.168.0.12",
			"notes": None,
			"type": "OpsiClient",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [["id"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": None,
			"notes": None,
			"type": "OpsiClient",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [[], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": "192.168.0.12",
			"notes": "pytest test data notes",
			"type": "OpsiClient",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [["bla"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 0,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": "192.168.0.12",
			"notes": "pytest test data notes",
			"type": "OpsiClient",
			"error": {
				"message": "Invalid attribute 'bla'",
				"class": "ValueError",
			}
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [[], {"notes": "no results for this request"}]},
		{
			"num_results": 0,
			"status_code": 200,
			"method": "host_getObjects",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [["ipAddress"], {"ipAddress": "192.168.0.111"}]},
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
def test_process_jsonrpc_request(config, fill_db, request_data, expected_result): # pylint: disable=unused-argument
	rpc_request_data = json.dumps(request_data)
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	print(result_json)

	assert res.status_code == expected_result.get("status_code")

	if result_json.get("error") is None:
		assert len(result_json.get("result")) == expected_result.get("num_results")
		if len(result_json.get("result")) > 0:
			assert result_json.get("result")[0].get("notes") == expected_result.get("notes")
			assert result_json.get("result")[0].get("ipAddress") == expected_result.get("ipAddress")
			assert result_json.get("result")[0].get("id") == expected_result.get("id")
			assert result_json.get("result")[0].get("type") == expected_result.get("type")
	else:
		error = result_json.get("error")
		expected_error = expected_result.get("error")
		assert error.get("message") == expected_error.get("message")
		assert error.get("class") == expected_error.get("class")


def test_create_OPSI_Client(config): # pylint: disable=invalid-name

	request_data = {
		"id": 1,
		"method": "host_createOpsiClient",
		"params": [
			"test.fabian.uib.local"
		]
	}

	rpc_request_data = json.dumps(request_data)

	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	print(result_json)
	# {"jsonrpc":"2.0","id":1,"method":"host_createOpsiClient","params":["test.fabian.uib.local",null,null,null,null,null,null,null,null,null,{}],"result":[],"error":null} # pylint: disable=line-too-long
	assert result_json.get("error") is None
	assert res.status_code == 200


	request_data = {
		"id": 1,
		"method": "host_getObjects",
		"params": [
			[],
			{
				"id": "test.fabian.uib.local"
			}
		]
	}

	rpc_request_data = json.dumps(request_data)
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	print("RESULT1: ", result_json)
	assert len(result_json.get("result")) == 1
	assert result_json.get("result")[0].get("id") == "test.fabian.uib.local"
	assert result_json.get("error") is None
	mysql_host = os.environ.get("MYSQL_HOST")
	if not mysql_host:
		mysql_host = "127.0.0.1"
	db=_mysql.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi") # pylint: disable=invalid-name, c-extension-no-member
	db.query('DELETE FROM HOST WHERE hostId like "test.fabian.uib.local";')



	rpc_request_data = json.dumps(request_data)
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	print("RESULT2: ", result_json)
	assert len(result_json.get("result")) == 0
	assert result_json.get("error") is None


def test_delete_OPSI_Client(config, fill_db): # pylint: disable=unused-argument, invalid-name

	request_data = {
		"id": 1,
		"method": "host_getObjects",
		"params": [
			[],
			{
				"id": "pytest4.uib.gmbh"
			}
		]
	}

	rpc_request_data = json.dumps(request_data)
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	print("RESULT1: ", result_json)
	assert len(result_json.get("result")) == 1
	assert result_json.get("result")[0].get("id") == "pytest4.uib.gmbh"
	assert result_json.get("error") is None


	delete_request = {
		"id": 1,
		"method": "host_delete",
		"params": ["pytest4.uib.gmbh"]
	}
	rpc_delete_request = json.dumps(delete_request)
	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_delete_request, verify=False)
	assert res.status_code == 200
	result_json = json.loads(res.text)
	print("Del result: ", result_json)

	assert result_json.get("error") is None
	assert result_json.get("result") is None


	res = requests.post(f"{config.internal_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	print("RESULT2: ", result_json)
	assert len(result_json.get("result")) == 0
	assert result_json.get("error") is None
