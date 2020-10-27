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

@pytest.fixture()
def fill_db():
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
	for data in mysql_data:
		db=_mysql.connect(host="mysql",user="opsi",passwd="opsi",db="opsi")
		sql_string = f'INSERT INTO HOST (hostId, type, description, notes,  hardwareAddress, ipAddress, inventoryNumber, created, lastSeen) VALUES (\"{data["hostId"]}\", \"{data["type"]}\", \"{data["description"]}\", \"{data["notes"]}\", \"{data["hardwareAddress"]}\", \"{data["ipAddress"]}\", \"{data["inventoryNumber"]}\", \"{data["created"]}\",  \"{data["lastSeen"]}\");'
		print(sql_string)
		db.query(sql_string)
		db.query(f'SELECT * FROM HOST WHERE ipAddress like \"{data["ipAddress"]}\";')
		r=db.store_result()
		print(r.fetch_row(maxrows=0))
	
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
				"message": "(1054, \"Unknown column 'bla' in 'field list'\")",
				"class": "OperationalError",
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
def test_process_jsonrpc_request(fill_db, request_data, expected_result):
	rpc_request_data = json.dumps(request_data)
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print(result_json)

	assert r.status_code == expected_result.get("status_code")
	
	if result_json.get("error") == None:
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


def test_create_OPSI_Client():

	request_data = {
		"id": 1,
		"method": "host_createOpsiClient",
		"params": [
			"test.fabian.uib.local"
		]
	}

	rpc_request_data = json.dumps(request_data)

	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print(result_json)
	# {"jsonrpc":"2.0","id":1,"method":"host_createOpsiClient","params":["test.fabian.uib.local",null,null,null,null,null,null,null,null,null,{}],"result":[],"error":null}
	assert result_json.get("error") == None
	assert r.status_code == 200


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
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print("RESULT1: ", result_json)
	assert len(result_json.get("result")) == 1
	assert result_json.get("result")[0].get("id") == "test.fabian.uib.local"
	assert result_json.get("error") == None

	db=_mysql.connect(host="mysql",user="opsi",passwd="opsi",db="opsi")
	db.query('DELETE FROM HOST WHERE hostId like "test.fabian.uib.local";')



	rpc_request_data = json.dumps(request_data)
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print("RESULT2: ", result_json)
	assert len(result_json.get("result")) == 0
	assert result_json.get("error") == None


def test_delete_OPSI_Client(fill_db):

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
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print("RESULT1: ", result_json)
	assert len(result_json.get("result")) == 1
	assert result_json.get("result")[0].get("id") == "pytest4.uib.gmbh"
	assert result_json.get("error") == None


	delete_request = {
		"id": 1,
		"method": "host_delete",
		"params": ["pytest4.uib.gmbh"]
	}
	rpc_delete_request = json.dumps(delete_request)
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_delete_request, verify=False)
	assert r.status_code == 200
	result_json = json.loads(r.text)
	print("Del result: ", result_json)
	
	assert result_json.get("error") == None
	assert result_json.get("ressult") == None


	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print("RESULT2: ", result_json)
	assert len(result_json.get("result")) == 0
	assert result_json.get("error") == None
