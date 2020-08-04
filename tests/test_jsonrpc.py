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
	# TODO assert mysql results
	# TODO insert more Data
	db=_mysql.connect(host="mysql",user="opsi",passwd="opsi",db="opsi")
	db.query("INSERT INTO HOST (description, notes, hostId, ipAddress, inventoryNumber, type, hardwareAddress) VALUES (\"\", \"pytest test data\", \"pytest.uib.gmbh\", \"192.168.0.12\", 0815, \"OpsiClient\", \"32:58:fd:f7:3b:26\");")
	db.query("SELECT * FROM HOST WHERE ipAddress like \"192.168.0.12\";")
	r=db.store_result()
	print(r.fetch_row(maxrows=0))
	yield None
	db.query("DELETE FROM HOST WHERE ipAddress like \"192.168.0.12\";")



jsonrpc_test_data = [
	(
		{"id": 1, "method": "host_getObjects", "params": [["ipAddress","id","notes"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1, 
			"status_code": 200,
			"method": "host_getObjects", 
			"id": "pytest.uib.gmbh", 
			"ipAddress": "192.168.0.12", 
			"notes": "pytest test data", 
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
			"notes": None, "type": 
			"OpsiClient",
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
			"notes": "pytest test data", 
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
			"notes": "pytest test data", 
			"type": "OpsiClient",
			"error": {
				"message": "(1054, \"Unknown column 'bla' in 'field list'\")",
				"class": "OperationalError",
				"details": "Traceback (most recent call last):\n  File \"/poetry/opsiconfd/application/jsonrpc.py\", line 234, in process_rpc\n    result = method(*params, **keywords)\n  File \"<string>\", line 1, in host_getObjects\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/Base/Extended.py\", line 137, in _executeMethod\n    return meth(**kwargs)\n  File \"<string>\", line 1, in host_getObjects\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/Base/Extended.py\", line 137, in _executeMethod\n    return meth(**kwargs)\n  File \"<string>\", line 1, in host_getObjects\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/Manager/AccessControl.py\", line 435, in _executeMethodProtected\n    result = meth(**newKwargs)\n  File \"<string>\", line 1, in host_getObjects\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/Base/Extended.py\", line 137, in _executeMethod\n    return meth(**kwargs)\n  File \"<string>\", line 1, in host_getObjects\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/Base/Extended.py\", line 137, in _executeMethod\n    return meth(**kwargs)\n  File \"<string>\", line 1, in host_getObjects\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/Base/Extended.py\", line 137, in _executeMethod\n    return meth(**kwargs)\n  File \"<string>\", line 1, in host_getObjects\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/Base/Extended.py\", line 137, in _executeMethod\n    return meth(**kwargs)\n  File \"<string>\", line 1, in host_getObjects\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/Manager/Dispatcher.py\", line 198, in _dispatchMethod\n    res = meth(**kwargs)\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/SQL.py\", line 1094, in host_getObjects\n    for res in self._sql.getSet(self._createQuery('HOST', attributes, filter)):\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/MySQL.py\", line 332, in getSet\n    self.execute(query, conn, cursor)\n  File \"/poetry/.venv/lib/python3.7/site-packages/OPSI/Backend/MySQL.py\", line 539, in execute\n    res = cursor.execute(query)\n  File \"/poetry/.venv/lib/python3.7/site-packages/MySQLdb/cursors.py\", line 209, in execute\n    res = self._query(query)\n  File \"/poetry/.venv/lib/python3.7/site-packages/MySQLdb/cursors.py\", line 315, in _query\n    db.query(q)\n  File \"/poetry/.venv/lib/python3.7/site-packages/MySQLdb/connections.py\", line 239, in query\n    _mysql.connection.query(self, query)\nMySQLdb._exceptions.OperationalError: (1054, \"Unknown column 'bla' in 'field list'\")\n"
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
	)

]

@pytest.mark.parametrize("request_data, expected_result", jsonrpc_test_data)
def test_process_jsonrpc_request(fill_db, request_data, expected_result):
	rpc_request_data = json.dumps(request_data)
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print(result_json)

	assert r.status_code == expected_result.get("status_code")
	assert result_json.get("method") == expected_result.get("method")
	
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
		assert error.get("details") == expected_error.get("details")

