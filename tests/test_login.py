import os
import sys
import pytest
import asyncio

import aredis
import requests

from opsiconfd.config import config


OPSI_URL = "https://localhost:4447" 
TEST_USER = "adminuser"
TEST_PW = "adminuser"


login_test_data = [
	(None, 401, "Authorization header missing"),
	((None,None), 401, "Backend authentication error: <BackendAuthenticationError(\"Authentication failed for user 'None': Backend authentication error: PAM authentication failed for user 'None': Authentication failure\")>"),
	(("",""), 401, "Backend authentication error: No username specified"),
	((TEST_USER,""), 401, "Backend authentication error: No password specified"),
	(("",TEST_PW), 401, "Backend authentication error: No username specified"),
]

_redis_client = None

async def get_redis_client():
	global _redis_client
	if not _redis_client:
		# The client automatically uses a connection from a connection pool for every command 
		_redis_client = aredis.StrictRedis.from_url("redis://redis")
	return _redis_client

@pytest.mark.asyncio
@pytest.mark.parametrize("auth_data, expected_status_code, expected_text", login_test_data)
async def test_without_login(auth_data, expected_status_code, expected_text):
	
	r = requests.get(OPSI_URL, auth=(auth_data) ,verify=False)
	assert r.status_code == expected_status_code
	assert r.text == expected_text
	assert r.headers.get("set-cookie", None) != None 
	session_id = r.headers.get("set-cookie").split(";")[0].split("=")[1]
	redis_client = await get_redis_client()
	await redis_client.delete(f"opsiconfd-session:172.19.0.1:{session_id}")

def test_login():
	r = requests.get(OPSI_URL, auth=("adminuser","adminuser"), verify=False)
	assert r.status_code == 200
	assert r.url == f"{OPSI_URL}/static/index.html"
	