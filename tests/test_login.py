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

from OPSI.Util import ipAddressInNetwork

from opsiconfd.config import config

OPSI_URL = "https://127.0.0.1:4447"
TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"


@pytest.fixture(autouse=True)
def clean_redis():
	yield None
	redis_client = redis.StrictRedis.from_url("redis://redis")
	redis_client.delete("opsiconfd:stats:client:failed_auth:127.0.0.1")
	redis_client.delete("opsiconfd:stats:client:blocked:127.0.0.1")
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:127.0.0.1:*")
	for key in session_keys:
		redis_client.delete(key)
	time.sleep(10)

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
def test_false_login(auth_data, expected_status_code, expected_text):
	
	r = requests.get(OPSI_URL, auth=(auth_data), verify=False)
	assert r.status_code == expected_status_code
	assert r.text == expected_text
	assert r.headers.get("set-cookie", None) != None 

def test_proper_login():

	print(OPSI_URL)
	print(TEST_USER)
	print(TEST_PW)
	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{OPSI_URL}/admin"

@pytest.mark.skip(reason="test does not work in gitlab ci")
def test_max_sessions_client():
	print(config.max_session_per_ip)
	redis_client = redis.StrictRedis.from_url("redis://redis")
	for i in range(0,40):
		session_id = str(uuid.uuid4()).replace("-", "")
		print(f"{OPSI_SESSION_KEY}:127.0.0.1:{session_id}", value=f"empty test session {i}", time=120)
	print(redis_client.keys(f"{OPSI_SESSION_KEY}:*"))
	r = requests.get(OPSI_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 403
	assert r.text == "Too many sessions on '127.0.0.1'. Max is 25."
	print(r.text)
	time.sleep(130)
	r = requests.get(OPSI_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{OPSI_URL}/admin"

def test_max_auth():
	for i in range(0,15):
		r = requests.get(OPSI_URL, auth=("false_user","false_pw"), verify=False)
		print(r.status_code)
		if i >= 12:
			assert r.status_code == 403
			assert r.text == "Client '127.0.0.1' is blocked for 2.00 minutes!"
	time.sleep(120)
	r = requests.get(OPSI_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{OPSI_URL}/admin"
