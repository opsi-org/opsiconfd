# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import sys
import time
import uuid
import socket
import asyncio
import pytest
import urllib3
import redis
import aredis

import requests

FQDN = socket.getfqdn()
CONFD_URL = f"https://{FQDN}:4447"

# from opsiconfd.config import config

TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)

@pytest.fixture(name="config")
def fixture_config(monkeypatch):
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

	res = requests.get(CONFD_URL, auth=(auth_data), verify=False)
	print(auth_data)
	print(res.status_code)
	assert res.status_code == expected_status_code
	assert res.text == expected_text
	assert res.headers.get("set-cookie", None) is not None
	time.sleep(10)

def test_proper_login(config):

	print(CONFD_URL)
	print(TEST_USER)
	print(TEST_PW)
	res = requests.get(CONFD_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert res.status_code == 200
	assert res.url == f"{CONFD_URL}/admin"
	time.sleep(10)

@pytest.mark.skip(reason="test does not work in gitlab ci")
def test_max_sessions_client(config):
	print(config.max_session_per_ip)
	redis_client = redis.StrictRedis.from_url(config.redis_internal_url)
	for i in range(0,40):
		session_id = str(uuid.uuid4()).replace("-", "")
		print(f"{OPSI_SESSION_KEY}:{LOCAL_IP}:{session_id}", value=f"empty test session {i}", time=120)
	print(redis_client.keys(f"{OPSI_SESSION_KEY}:*"))
	res = requests.get(CONFD_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert res.status_code == 403
	assert res.text == f"Too many sessions on '{LOCAL_IP}'. Max is 25."
	print(res.text)
	time.sleep(130)
	res = requests.get(CONFD_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert res.status_code == 200
	assert res.url == f"{CONFD_URL}/admin"

def test_max_auth(config):
	session = requests.Session()
	for i in range(0,30):
		res = session.get(CONFD_URL, auth=("false_user","false_pw"), verify=False)
		print(res.status_code)
		if i >= 26:
			assert res.status_code == 403
			assert res.text == f"Client '{LOCAL_IP}' is blocked"
	time.sleep(120)
	res = session.get(CONFD_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert res.status_code == 200
	assert res.url == f"{CONFD_URL}/admin"
