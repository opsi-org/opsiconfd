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


def test_process_jsonrpc_request(fill_db):
	data = {"id": 1, "method": "host_getObjects", "params": [["ipAddress","id","notes"], {"ipAddress": "192.168.0.12"}]}
	rpc_request_data = json.dumps(data)
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print(result_json)

	assert r.status_code == 200
	assert len(result_json.get("result")) == 1
	assert result_json.get("result")[0].get("notes") == "pytest test data"
	assert result_json.get("result")[0].get("ipAddress") == "192.168.0.12"
	assert result_json.get("result")[0].get("id") == "pytest.uib.gmbh"
	assert result_json.get("method") == "host_getObjects"
