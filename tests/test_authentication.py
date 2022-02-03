# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
login tests
"""

import time
import pytest

from .utils import (  # pylint: disable=unused-import
	config,
	get_config,
	clean_redis,
	database_connection,
	ADMIN_USER,
	ADMIN_PASS,
	OPSI_SESSION_KEY,
	sync_redis_client,
	test_client,
)


login_test_data = [
	(None, 401, "Authorization header missing"),
	(("", ""), 401, "Authentication error"),
	((ADMIN_USER, ""), 401, "Authentication error"),
	((ADMIN_USER, "123"), 401, "Authentication error"),
	(("", ADMIN_PASS), 401, "Authentication error"),
	(("123", ADMIN_PASS), 401, "Authentication error"),
]


@pytest.mark.parametrize("auth_data, expected_status_code, expected_text", login_test_data)
def test_login_error(test_client, auth_data, expected_status_code, expected_text):  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.get("/", auth=(auth_data))
	assert res.status_code == expected_status_code
	assert res.text == expected_text
	assert res.headers.get("set-cookie", None) is not None


def test_login_success(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	assert res.url.rstrip("/") == f"{test_client.base_url}/admin"


def test_networks(test_client):  # pylint: disable=redefined-outer-name
	test_client.set_client_address("1.2.3.4", 12345)
	with get_config({"networks": ["0.0.0.0/0"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

	with get_config({"networks": ["10.0.0.0/8"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 403


def test_admin_networks(test_client):  # pylint: disable=redefined-outer-name
	test_client.set_client_address("1.2.3.4", 12345)
	with get_config({"networks": ["0.0.0.0/0"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

	with get_config({"networks": ["10.0.0.0/8"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 403


def test_public_access_get(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.get("/public")
	assert res.status_code == 200


def test_public_access_put(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.put("/public/test.bin", data=b"test")
	assert res.status_code == 405


def test_max_sessions(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	test_client.set_client_address("192.168.1.1", 12345)
	max_session_per_ip = 10
	over_limit = 3
	with (get_config({"max_session_per_ip": max_session_per_ip}), sync_redis_client() as redis):
		for num in range(1, max_session_per_ip + 1 + over_limit):
			res = test_client.get("/admin/", auth=(ADMIN_USER, ADMIN_PASS))
			if num > max_session_per_ip:
				print(res.status_code)
				print(res.text)
				assert res.status_code == 403
				assert res.text.startswith("Too many sessions")
			else:
				assert res.status_code == 200
			test_client.reset_cookies()

		# Delete some sessions
		num = 0
		for key in redis.scan_iter(f"{OPSI_SESSION_KEY}:*"):
			num += 1
			redis.delete(key)
			if num > over_limit:
				break

		res = test_client.get("/admin/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200


def test_max_auth_failures(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	over_limit = 3
	max_auth_failures = 10
	with (get_config({"max_auth_failures": max_auth_failures}) as conf, sync_redis_client() as redis):
		for num in range(max_auth_failures + over_limit):
			now = round(time.time()) * 1000
			for key in redis.scan_iter("opsiconfd:stats:client:failed_auth:*"):
				# print("=== key ==>>>", key)
				cmd = (
					f"ts.range {key.decode()} "
					f"{(now-(conf.auth_failures_interval*1000))} {now} aggregation count {(conf.auth_failures_interval*1000)}"
				)
				num_failed_auth = redis.execute_command(cmd)
				num_failed_auth = int(num_failed_auth[-1][1])
				# print("=== num_failed_auth ==>>>", num_failed_auth)

			res = test_client.get("/admin/", auth=("client.domain.tld", "hostkey"))
			# print("===>>>", num, max_auth_failures, res.status_code)
			if num > max_auth_failures:
				assert res.status_code == 403
				assert "blocked" in res.text
			else:
				assert res.status_code == 401
				assert res.text == "Authentication error"
			time.sleep(0.5)


def test_session_expire(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	lifetime = 5  # 5 seconds
	lt_headers = {"x-opsi-session-lifetime": str(lifetime)}

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	res = test_client.get("/admin/", headers=lt_headers)
	cookie = list(test_client.cookies)[0]
	session_id = cookie.value
	assert res.status_code == 200
	remain = cookie.expires - time.time()
	assert remain <= lifetime
	assert remain >= lifetime - 2

	# Let session expire
	time.sleep(lifetime + 1)

	res = test_client.get("/admin/", headers=lt_headers)
	cookie = list(test_client.cookies)[0]
	# Assert new session
	assert res.status_code == 200
	assert session_id != cookie.value

	remain = cookie.expires - time.time()
	assert remain <= lifetime
	assert remain >= lifetime - 2

	session_id = cookie.value
	test_client.auth = None
	# Keep session alive
	for _ in range(lifetime + 3):
		time.sleep(1)
		res = test_client.get("/admin/")
		assert res.status_code == 200
		cookie = list(test_client.cookies)[0]
		assert session_id == cookie.value

	# Let session expire
	time.sleep(lifetime + 1)
	res = test_client.get("/admin/")
	assert res.status_code == 401


def test_onetime_password_host_id(test_client, database_connection):  # pylint: disable=redefined-outer-name,unused-argument
	database_connection.query(
		"""
		INSERT INTO HOST
			(hostId, type, opsiHostKey, oneTimePassword)
		VALUES
			("onetimepasswd.uib.gmbh", "OpsiClient", "f020dcde5108508cd947c5e229d9ec04", "onet1me");
	"""
	)
	database_connection.commit()
	try:
		rpc = {"id": 1, "method": "backend_info", "params": []}
		res = test_client.get("/rpc", auth=("onetimepasswd.uib.gmbh", "onet1me"), json=rpc)
		assert res.status_code == 200
		assert res.json()

		test_client.reset_cookies()
		res = test_client.get("/rpc", auth=("onetimepasswd.uib.gmbh", "onet1me"), json=rpc)
		assert res.status_code == 401
	finally:
		database_connection.query('DELETE FROM HOST WHERE hostId = "onetimepasswd.uib.gmbh"')
		database_connection.commit()


def test_onetime_password_hardware_address(test_client, database_connection):  # pylint: disable=redefined-outer-name,unused-argument
	database_connection.query(
		"""
		INSERT INTO HOST
			(hostId, type, opsiHostKey, oneTimePassword, hardwareAddress)
		VALUES
			("onetimepasswd.uib.gmbh", "OpsiClient", "f020dcde5108508cd947c5e229d9ec04", "onet1mac", "01:02:aa:bb:cc:dd");
	"""
	)
	database_connection.commit()
	try:
		rpc = {"id": 1, "method": "backend_info", "params": []}
		res = test_client.get("/rpc", auth=("01:02:aa:bb:cc:dd", "onet1mac"), json=rpc)
		assert res.status_code == 200
		assert res.json()

		test_client.reset_cookies()
		res = test_client.get("/rpc", auth=("01:02:aa:bb:cc:dd", "onet1mac"), json=rpc)
		assert res.status_code == 401
	finally:
		database_connection.query('DELETE FROM HOST WHERE hostId = "onetimepasswd.uib.gmbh"')
		database_connection.commit()
