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

from fastapi.testclient import TestClient

from MySQLdb import _mysql



# import nest_asyncio

OPSI_URL = "https://localhost:4447" 
TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"

# from opsiconfd.application.main import app


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
	print("????")
	db=_mysql.connect(host="172.19.0.1",port=3307,user="opsi",passwd="opsi",db="opsi")
	db.query("INSERT INTO HOST (description, notes, hostId, ipAddress, inventoryNumber, type, hardwareAddress) VALUES (\"\", \"pytest test data\", \"pytest.uib.gmbh\", \"192.168.0.12\", 0815, \"OpsiClient\", \"32:58:fd:f7:3b:26\");")
	db.query("SELECT * FROM HOST WHERE ipAddress like \"192.168.0.12\";")
	r=db.store_result()
	print(r.fetch_row(maxrows=0))
	yield None
	db.query("DELETE FROM HOST WHERE ipAddress like \"192.168.0.12\";")
	print("????")
	
	

# @pytest.fixture
# def client(monkeypatch):
# 	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
# 	from opsiconfd.application.main import app, application_setup
# 	application_setup()
# 	client = TestClient(app)
# 	return client

@pytest.fixture
def app(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.application.main import app, application_setup
	application_setup()
	return app


def test_process_jsonrpc_request(fill_db):
	data = {"id": 1, "method": "host_getObjects", "params": [["ipAddress","id","notes"], {"ipAddress": "192.168.0.12"}]}
	rpc_request_data = json.dumps(data)
	r = requests.post(f"{OPSI_URL}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(r.text)

	print(result_json)
	print("!!!!")
	assert r.status_code == 200
	assert len(result_json.get("result")) == 1
	assert result_json.get("result")[0].get("notes") == "pytest test data"
	assert result_json.get("result")[0].get("ipAddress") == "192.168.0.12"
	assert result_json.get("result")[0].get("id") == "pytest.uib.gmbh"
	assert result_json.get("method") == "host_getObjects"
	


# def test_jsonrpc(app):
# 	# nest_asyncio.apply()
# 	client = TestClient(app)
# 	client.base_url = "https://127.0.0.1"
# 	print(client.__dict__)
# 	client.auth=(TEST_USER, TEST_PW)
# 	print(client.__dict__)
# 	headers_content = {'host': 'localhost:4447', 'connection': 'keep-alive', 'content-length': '50', 'authorization': 'Basic YWRtaW51c2VyOmFkbWludXNlcg==', 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 Chrome/83.0.4103.61 Safari/537.36', 'content-type': 'text/plain;charset=UTF-8', 'accept': '*/*', 'origin': 'https://localhost:4447', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://localhost:4447/admin', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7', 'cookie': f'grafana_session=f3a753ebd846a991316e01ec0afbc919; opsiconfd-session=f3a753ebd846a991316e01ec0afbc919'}
# 	client.headers = headers_content
# 	print("------------")
# 	print(client.__dict__)
# 	print("------------")
# 	attempt = client.get("/rpc")
# 	assert attempt.status_code == 200

	# headers_content = {'host': 'localhost:4447', 'connection': 'keep-alive', 'content-length': '50', 'authorization': 'Basic YWRtaW51c2VyOmFkbWludXNlcg==', 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 Chrome/83.0.4103.61 Safari/537.36', 'content-type': 'text/plain;charset=UTF-8', 'accept': '*/*', 'origin': 'https://localhost:4447', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://localhost:4447/admin', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7', 'cookie': f'grafana_session=f3a753ebd846a991316e01ec0afbc919; opsiconfd-session=f3a753ebd846a991316e01ec0afbc919'}
	# data = {"id": 1, "method": "host_getIdents", "params": [None]}
	# rpc_request_data = json.dumps(data)
	# r = client.get("/rpc-list", headers=headers_content, auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)

	# print(r.status_code)
	# print(r.headers)
	# print(r.text)

	# assert 1 == 0

# def test_process_jsonrpc(fastapi):
# 	headers_content = {'host': 'localhost:4447', 'connection': 'keep-alive', 'content-length': '50', 'authorization': 'Basic YWRtaW51c2VyOmFkbWludXNlcg==', 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 Chrome/83.0.4103.61 Safari/537.36', 'content-type': 'text/plain;charset=UTF-8', 'accept': '*/*', 'origin': 'https://localhost:4447', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://localhost:4447/admin', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7', 'cookie': f'grafana_session=f3a753ebd846a991316e01ec0afbc919; opsiconfd-session=f3a753ebd846a991316e01ec0afbc919'}

# 	client = TestClient(fastapi)
# 	client.base_url = OPSI_URL
# 	client.headers = headers_content
# 	print(client.__repr__())
# 	print(client.__dict__)

# 	data = {"id": 1, "method": "host_getIdents", "params": [None]}
# 	rpc_request_data = json.dumps(data)


# 	r = client.get("/rpc-list", headers=headers_content, auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)

# 	print(r.text)
# 	print(r.status_code)

# 	assert 1 == 0