import os
import sys
import pytest
import time

import requests

from opsiconfd.config import config
from OPSI.Util import ipAddressInNetwork

import uuid
import urllib3
import redis


OPSI_URL = "https://localhost:4447" 
TEST_USER = "adminuser"
TEST_PW = "adminuser"

@pytest.fixture(autouse=True)
def clean_redis():
	yield None
	redis_client = redis.StrictRedis.from_url("redis://redis")
	redis_client.delete("opsiconfd:stats:client:failed_auth:127.0.0.1")
	redis_client.delete("opsiconfd:stats:client:blocked:127.0.0.1")
	session_keys = redis_client.scan_iter("opsiconfd-session:*")
	for key in session_keys:
		redis_client.delete(key)

@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

login_test_data = [
	(None, 401, "Authorization header missing"),
	# ((None, None), 401, "Backend authentication error: <BackendAuthenticationError(\"Authentication failed for user 'None': Backend authentication error: PAM authentication failed for user 'None': Authentication failure\")>"),
	(("", ""), 401, "Backend authentication error: No username specified"),
	((TEST_USER, ""), 401, "Backend authentication error: No password specified"),
	((TEST_USER, "123"), 401, "Backend authentication error: <BackendAuthenticationError(\"Authentication failed for user 'adminuser': Backend authentication error: PAM authentication failed for user 'adminuser': Authentication failure\")>"),
	(("", TEST_PW), 401, "Backend authentication error: No username specified"),
	(("123", TEST_PW), 401, "Backend authentication error: <BackendAuthenticationError(\"Authentication failed for user '123': Backend authentication error: PAM authentication failed for user '123': Authentication failure\")>")
]

@pytest.mark.parametrize("auth_data, expected_status_code, expected_text", login_test_data)
def test_false_login(auth_data, expected_status_code, expected_text):
	# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	
	r = requests.get(OPSI_URL, auth=(auth_data), verify=False)
	assert r.status_code == expected_status_code
	assert r.text == expected_text
	assert r.headers.get("set-cookie", None) != None 

def test_proper_login():
	# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	print(OPSI_URL)
	print(TEST_USER)
	print(TEST_PW)
	r = requests.get(OPSI_URL, auth=(TEST_USER, TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{OPSI_URL}/static/index.html"

def test_max_sessions_client():
	print(config.max_session_per_ip)
	for i in range(0,26):
		session_id = str(uuid.uuid4()).replace("-", "")
		print(f"opsiconfd-session:127.0.0.1:{session_id}")
		redis_client = redis.StrictRedis.from_url("redis://redis")
		redis_client.setex(name=f"opsiconfd-session:127.0.0.1:{session_id}", value=f"empty test session {i}", time=20)
	r = requests.get(OPSI_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 403
	assert r.text == "Too many sessions on '127.0.0.1'. Max is 25."
	print(r.text)
	time.sleep(30)
	r = requests.get(OPSI_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{OPSI_URL}/static/index.html"

def test_max_auth():
	for i in range(0,12):
		r = requests.get(OPSI_URL, auth=("false_user","dalse_pw"), verify=False)
		print(r.status_code)
		if i >= 9:
			assert r.status_code == 403
			assert r.text == "Client '127.0.0.1' is blocked for 2.00 minutes!"
	time.sleep(120)
	r = requests.get(OPSI_URL, auth=(TEST_USER,TEST_PW), verify=False)
	assert r.status_code == 200
	assert r.url == f"{OPSI_URL}/static/index.html"

# def test_admin_network():
# 	config._parse_args(["--admin-networks", "10.10.10.0/24"])
	
	# assert config.admin_networks == ["0.0.0.0/0"]
	# print(config.admin_networks)
	# # print(os.environ["OPSICONFD_ADMIN_NETWORKS"])
	# # config.admin_networks = ['192.168.2.0/24']
	# os.environ["OPSICONFD_ADMIN_NETWORKS"] = "['192.168.2.0/24']"
	
	# # config._parse_args(["--admin-networks", "10.10.10.0/24"])
	# networks = config.admin_networks
	# print(config.admin_networks)
	# for network in networks:
	# 	ip_adress_in_network = ipAddressInNetwork("127.0.0.1", network)
	# 	print(ip_adress_in_network)
	# r = requests.get("https://localhost:4447/static/log_viewer.html", auth=(TEST_USER,TEST_PW), verify=False)
	# assert r.status_code == 403
	# assert r.text == f"User not in admin network '{config.admin_networks}'"
	# # config.admin_networks = ["0.0.0.0/0"]
	# config._parse_args(["--admin-networks", "10.10.10.0/24"])
	# r = requests.get(OPSI_URL, auth=(TEST_USER,TEST_PW), verify=False)
	# assert r.status_code == 200
	# print(config.items())
	# assert config.admin_networks == ""