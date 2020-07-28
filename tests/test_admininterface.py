import os
import sys
import pytest
import time
import uuid
import urllib3
import redis
import requests

from OPSI.Util import ipAddressInNetwork


OPSI_URL = "https://localhost:4447" 
TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"

@pytest.fixture(autouse=True)
def clean_redis():
	yield None
	redis_client = redis.StrictRedis.from_url("redis://redis")
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:127.0.0.1:*")
	for key in session_keys:
		# print(key)
		redis_client.delete(key)
	redis_client.delete("opsiconfd:stats:client:failed_auth:127.0.0.1")
	redis_client.delete("opsiconfd:stats:client:blocked:127.0.0.1")
	

@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_unblock_all():
	admin_request = requests.get(f"{OPSI_URL}/admin", auth=("adminuser","adminuser"), verify=False)
	for i in range(0, 15):
		r = requests.get(OPSI_URL, auth=("false_user","false_pw"), verify=False)
		if i >= 12:
			assert r.status_code == 403
			assert r.text == "Client '127.0.0.1' is blocked for 2.00 minutes!"

	admin_request = requests.post(f"{OPSI_URL}/admin/unblock-all", auth=("adminuser","adminuser"), cookies=admin_request.cookies, verify=False)
	assert admin_request.status_code == 200

	r = requests.get(OPSI_URL, auth=("adminuser","adminuser"), verify=False)
	assert r.status_code == 200


def test_unblock_client():
	admin_request = requests.get(f"{OPSI_URL}/admin", auth=("adminuser","adminuser"), verify=False)
	for i in range(0, 15):
		r = requests.get(OPSI_URL, auth=("false_user","false_pw"), verify=False)
		if i >= 12:
			assert r.status_code == 403
			assert r.text == "Client '127.0.0.1' is blocked for 2.00 minutes!"
	
	admin_request = requests.post(f"{OPSI_URL}/admin/unblock-client", auth=("adminuser","adminuser"), data="{\"client_addr\": \"127.0.0.1\"}", cookies=admin_request.cookies, verify=False)
	assert admin_request.status_code == 200
	print("unblock-client")
	print(admin_request.text)
	print(admin_request.status_code)

	r = requests.get(OPSI_URL, auth=("adminuser","adminuser"), verify=False)
	assert r.status_code == 200