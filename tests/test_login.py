import os
import sys
import pytest

import requests

from opsiconfd.config import config

import urllib3
import redis


OPSI_URL = "https://localhost:4447" 
TEST_USER = "adminuser"
TEST_PW = "adminuser"


# @pytest.fixture
# def disable_insecure_warning():
#     urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@pytest.fixture(autouse=True)
def clean_redis():
	yield None
	redis_client = redis.StrictRedis.from_url("redis://redis")
	redis_client.delete("opsiconfd:stats:client:failed_auth:127.0.0.1")

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
def test_without_login(auth_data, expected_status_code, expected_text):
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	
	r = requests.get(OPSI_URL, auth=(auth_data) ,verify=False)
	assert r.status_code == expected_status_code
	assert r.text == expected_text
	assert r.headers.get("set-cookie", None) != None 

	# redis_client = redis.StrictRedis.from_url("redis://redis")
	# redis_client.delete("opsiconfd:stats:client:failed_auth:127.0.0.1")

def test_login():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	
	r = requests.get(OPSI_URL, auth=("adminuser","adminuser"), verify=False)
	assert r.status_code == 200
	assert r.url == f"{OPSI_URL}/static/index.html"

	