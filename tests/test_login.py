import os
import sys
import pytest
import time
import uuid
import urllib3
import redis
import aredis
import asyncio
import requests
import socket
from OPSI.Util import ipAddressInNetwork


# from opsiconfd.config import config

TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)

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

login_test_data = [
	(None, 401, ""),
	(("", ""), 401, "Authentication error"),
	((TEST_USER, ""), 401, "Authentication error"),
	((TEST_USER, "123"), 401, "Authentication error"),
	(("", TEST_PW), 401, "Authentication error"),
	(("123", TEST_PW), 401, "Authentication error")
]

@pytest.mark.parametrize("auth_data, expected_status_code, expected_text", login_test_data)
def test_false_login(config, auth_data, expected_status_code, expected_text):
	
	r = requests.get(config.internal_url, auth=(auth_data), verify=False)
	print(auth_data)
	print(r.status_code)
	assert r.status_code == expected_status_code
	assert r.text == expected_text
	assert r.headers.get("set-cookie", None) != None 
	time.sleep(10)

def test_proper_login(config):

	print(config.internal_url)
	print(TEST_USER)
	print(TEST_PW)
	r = requests.get(config.internal_url, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{config.internal_url}/admin"
	time.sleep(10)

@pytest.mark.skip(reason="test does not work in gitlab ci")
def test_max_sessions_client(config):
	print(config.max_session_per_ip)
	redis_client = redis.StrictRedis.from_url(config.redis_internal_url)
	for i in range(0,40):
		session_id = str(uuid.uuid4()).replace("-", "")
		print(f"{OPSI_SESSION_KEY}:{LOCAL_IP}:{session_id}", value=f"empty test session {i}", time=120)
	print(redis_client.keys(f"{OPSI_SESSION_KEY}:*"))
	r = requests.get(config.internal_url, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 403
	assert r.text == f"Too many sessions on '{LOCAL_IP}'. Max is 25."
	print(r.text)
	time.sleep(130)
	r = requests.get(config.internal_url, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{config.internal_url}/admin"

def test_max_auth(config):
	for i in range(0,15):
		r = requests.get(config.internal_url, auth=("false_user","false_pw"), verify=False)
		print(r.status_code)
		if i >= 12:
			assert r.status_code == 403
			assert r.text == f"Client '{LOCAL_IP}' is blocked for 2.00 minutes!"
	time.sleep(120)
	r = requests.get(config.internal_url, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{config.internal_url}/admin"
