# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
login tests
"""

import json
import time
from datetime import datetime

import pyotp
import pytest
from MySQLdb.connections import Connection  # type: ignore[import]

from opsiconfd import (
	contextvar_client_session,
	get_contextvars,
	set_contextvars,
	set_contextvars_from_contex,
)
from opsiconfd.redis import ip_address_to_redis_key

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	config,
	database_connection,
	depot_jsonrpc,
	get_config,
	sync_redis_client,
	test_client,
)

login_test_data = (
	(None, 401, "Authorization header missing"),
	(("", ""), 401, "Authentication error"),
	((ADMIN_USER, ""), 401, "Authentication error"),
	((ADMIN_USER, "123"), 401, "Authentication error"),
	(("", ADMIN_PASS), 401, "Authentication error"),
	(("123", ADMIN_PASS), 401, "Authentication error"),
)


def test_get_session(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.get("/")
	cvars = get_contextvars()
	try:
		if test_client.context:
			set_contextvars_from_contex(test_client.context)
		assert contextvar_client_session.get()
	finally:
		set_contextvars(cvars)


@pytest.mark.parametrize("auth_data, expected_status_code, expected_text", login_test_data)
def test_login_error(
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name
	auth_data: tuple[str, str],
	expected_status_code: int,
	expected_text: str,
) -> None:
	res = test_client.get("/session/authenticated", auth=auth_data)
	assert res.status_code == expected_status_code
	assert res.text == expected_text
	assert res.headers.get("set-cookie", None) is not None


def test_x_requested_with_header(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	res = test_client.get("/session/authenticated")
	assert res.status_code == 401
	assert res.headers.get("www-authenticate", None) is not None

	res = test_client.get("/session/authenticated", headers={"X-Requested-With": "XMLHttpRequest"})
	assert res.status_code == 401
	assert res.headers.get("www-authenticate", None) is None


def test_basic_auth(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	assert str(res.url).rstrip("/") in [f"{test_client.base_url}/admin", f"{test_client.base_url}/welcome"]


def test_login_endpoint(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.post("/session/login", json={"username": ADMIN_USER, "password": "invalid"})
	assert res.status_code == 401
	assert "Authentication failed for user" in res.json()["message"]

	res = test_client.get("/session/authenticated")
	assert res.status_code == 401

	res = test_client.get("/admin", follow_redirects=False)
	assert res.status_code == 307

	res = test_client.post("/session/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
	assert res.json()["session_id"]
	assert res.status_code == 200

	res = test_client.get("/session/authenticated")
	assert res.status_code == 200

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "user_getObjects", "params": [[], {"id": ADMIN_USER}]}
	res = test_client.post("/rpc", json=rpc)
	assert res.status_code == 200
	resp = res.json()
	assert "error" not in resp
	assert resp["result"][0]["id"] == ADMIN_USER
	diff = datetime.now() - datetime.strptime(resp["result"][0]["created"], "%Y-%m-%d %H:%M:%S")
	assert abs(diff.total_seconds()) < 3
	diff = datetime.now() - datetime.strptime(resp["result"][0]["lastLogin"], "%Y-%m-%d %H:%M:%S")
	assert abs(diff.total_seconds()) < 3


def test_logout_endpoint(config: Config, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	with sync_redis_client() as redis:
		client_addr = "192.168.1.1"
		test_client.set_client_address(client_addr, 12345)

		res = test_client.get("/session/authenticated", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

		keys = sorted([key.decode() for key in redis.scan_iter(f"{config.redis_key('session')}:*")])
		assert len(keys) == 1
		assert keys[0].startswith(f"{config.redis_key('session')}:{ip_address_to_redis_key(client_addr)}:")

		res = test_client.get("/session/logout")
		assert res.status_code == 200
		assert "opsiconfd-session" in res.headers["set-cookie"]
		assert "Max-Age=0" in res.headers["set-cookie"]
		keys = sorted([key.decode() for key in redis.scan_iter(f"{config.redis_key('session')}:*")])
		assert len(keys) == 0


def test_mfa_totp(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	res = test_client.post("/session/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
	assert res.status_code == 200

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "user_activateMultiFactorAuth",
		"params": {"userId": ADMIN_USER, "type": "totp", "returnType": "uri"},
	}
	res = test_client.post("/rpc", json=rpc)
	assert res.status_code == 200
	resp = res.json()
	assert "error" not in resp
	assert resp["result"]
	totp = pyotp.parse_uri(resp["result"])

	res = test_client.post("/session/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
	assert res.status_code == 401
	assert "MFA one-time password missing" in res.json()["message"]

	res = test_client.post("/session/login", json={"username": ADMIN_USER, "password": ADMIN_PASS, "mfa_otp": "123456"})
	assert res.status_code == 401
	assert "Incorrect one-time password" in res.json()["message"]

	res = test_client.post(
		"/session/login", json={"username": ADMIN_USER, "password": ADMIN_PASS, "mfa_otp": totp.now()}  # type: ignore[attr-defined]
	)
	assert res.status_code == 200


def test_change_session_ip(
	config: Config, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	with sync_redis_client() as redis:
		client_addr = "192.168.1.1"
		test_client.set_client_address(client_addr, 12345)
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

		keys = sorted([key.decode() for key in redis.scan_iter(f"{config.redis_key('session')}:*")])
		assert len(keys) == 1
		assert keys[0].startswith(f"{config.redis_key('session')}:{ip_address_to_redis_key(client_addr)}:")

		client_addr = "192.168.2.2"
		test_client.set_client_address(client_addr, 12345)
		res = test_client.get("/session/authenticated")
		assert res.status_code == 401

		res = test_client.get("/session/authenticated", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

		keys = sorted([key.decode() for key in redis.scan_iter(f"{config.redis_key('session')}:*")])
		assert len(keys) == 2
		assert keys[1].startswith(f"{config.redis_key('session')}:{ip_address_to_redis_key(client_addr)}:")


def test_networks(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.set_client_address("1.2.3.4", 12345)
	with get_config({"networks": ["0.0.0.0/0"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

	with get_config({"networks": ["10.0.0.0/8"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 403


def test_admin_networks(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.set_client_address("1.2.3.4", 12345)
	with get_config({"networks": ["0.0.0.0/0"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

	with get_config({"networks": ["10.0.0.0/8"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 403


def test_public_access_get(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.get("/public")
	assert res.status_code == 200


def test_public_access_put(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.put("/public/test.bin", content=b"test")
	assert res.status_code == 405


def test_max_sessions_limit(
	config: Config, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.set_client_address("192.168.1.1", 12345)
	max_session_per_ip = 10
	over_limit = 3
	redis_key = f"{config.redis_key('session')}:*"
	with (get_config({"max_session_per_ip": max_session_per_ip}), sync_redis_client() as redis):
		for num in range(1, max_session_per_ip + 1 + over_limit):
			res = test_client.get("/admin/", auth=(ADMIN_USER, ADMIN_PASS))
			if num > max_session_per_ip:
				assert res.status_code == 403
				assert res.text.startswith("Too many sessions")
			else:
				assert res.status_code == 200
			test_client.reset_cookies()

		# Delete some sessions
		num = 0
		for key in redis.scan_iter(redis_key):
			num += 1
			redis.delete(key)
			if num > over_limit:
				break

		res = test_client.get("/admin/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200


def test_max_sessions_not_for_depot(
	config: Config, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.set_client_address("192.168.11.1", 12345)
	max_session_per_ip = 3
	over_limit = 30
	redis_key = f"{config.redis_key('session')}:*"
	depot_id = "test-depot-max-sessions.uib.local"
	depot_key = "29124776768a560d5e45d3c50889ec51"
	with depot_jsonrpc(test_client, "", depot_id, depot_key):
		test_client.reset_cookies()
		with (get_config({"max_session_per_ip": max_session_per_ip}), sync_redis_client() as redis):
			for _ in range(1, max_session_per_ip + 1 + over_limit):
				res = test_client.get("/depot", auth=(depot_id, depot_key))
				assert res.status_code == 200
				test_client.reset_cookies()

		session_keys = list(redis.scan_iter(redis_key))
		assert len(session_keys) >= max_session_per_ip + over_limit

		# Delete sessions
		for key in session_keys:
			redis.delete(key)


def test_max_auth_failures(
	config: Config, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	over_limit = 3
	max_auth_failures = 5
	with (get_config({"max_auth_failures": max_auth_failures}) as conf, sync_redis_client() as redis):
		for num in range(max_auth_failures + over_limit):
			now = round(time.time()) * 1000
			for key in redis.scan_iter(f"{config.redis_key('stats')}:client:failed_auth:*"):
				# print("=== key ==>>>", key)
				cmd = (
					f"ts.range {key.decode()} "
					f"{(now-(conf.auth_failures_interval*1000))} {now} aggregation count {(conf.auth_failures_interval*1000)}"
				)
				num_failed_auth = redis.execute_command(cmd)
				num_failed_auth = int(num_failed_auth[-1][1])
				# print("=== num_failed_auth ==>>>", num_failed_auth)

			res = test_client.get("/session/authenticated", auth=("client.domain.tld", "hostkey"))
			print("Auth: ", num, max_auth_failures, res.status_code)
			if num > max_auth_failures:
				assert res.status_code == 403
				assert "blocked" in res.text
			else:
				assert res.status_code == 401
				assert res.text == "Authentication error"
			time.sleep(2)


def test_session_expire(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	lifetime = 5  # 5 seconds
	lt_headers = {"x-opsi-session-lifetime": str(lifetime)}

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	res = test_client.get("/admin/", headers=lt_headers)
	cookie = list(test_client.cookies.jar)[0]
	session_id = cookie.value
	assert res.status_code == 200
	remain = cookie.expires - time.time()  # type: ignore[operator]
	assert remain <= lifetime
	assert remain >= lifetime - 2

	# Let session expire
	time.sleep(lifetime + 1)

	res = test_client.get("/admin/", headers=lt_headers)
	cookie = list(test_client.cookies.jar)[0]
	# Assert new session
	assert res.status_code == 200
	assert session_id != cookie.value

	remain = cookie.expires - time.time()  # type: ignore[operator]
	assert remain <= lifetime
	assert remain >= lifetime - 2

	session_id = cookie.value
	test_client.auth = None
	# Keep session alive
	for _ in range(lifetime + 3):
		time.sleep(1)
		res = test_client.get("/session/authenticated")
		assert res.status_code == 200
		cookie = list(test_client.cookies.jar)[0]
		assert session_id == cookie.value

	# Let session expire
	time.sleep(lifetime + 1)
	res = test_client.get("/session/authenticated")
	assert res.status_code == 401


def test_session_max_age(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	lifetime = 60
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	res = test_client.get("/admin/")
	# res = test_client.get("/admin/", headers=lt_headers)
	assert res.status_code == 200
	cookie = list(test_client.cookies.jar)[0]
	session_id = cookie.value
	remain = cookie.expires - time.time()  # type: ignore[operator]#
	print(remain)
	assert remain <= lifetime

	# wait for redis to store session info
	time.sleep(10)

	lifetime = 60 * 15  # 15 min
	lt_headers = {"x-opsi-session-lifetime": str(lifetime)}
	res = test_client.get("/admin/", headers=lt_headers)
	assert res.status_code == 200
	cookie = list(test_client.cookies.jar)[0]
	remain = cookie.expires - time.time()  # type: ignore[operator]
	print(remain)
	assert remain <= lifetime
	assert remain >= 100
	assert session_id == cookie.value


def test_onetime_password_host_id(
	test_client: OpsiconfdTestClient, database_connection: Connection  # pylint: disable=redefined-outer-name
) -> None:
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
		res = test_client.post("/rpc", auth=("onetimepasswd.uib.gmbh", "onet1me"), json=rpc)
		assert res.status_code == 200
		assert res.json()

		test_client.reset_cookies()
		res = test_client.post("/rpc", auth=("onetimepasswd.uib.gmbh", "onet1me"), json=rpc)
		assert res.status_code == 401
	finally:
		database_connection.query('DELETE FROM HOST WHERE hostId = "onetimepasswd.uib.gmbh"')
		database_connection.commit()


def test_onetime_password_hardware_address(
	test_client: OpsiconfdTestClient, database_connection: Connection  # pylint: disable=redefined-outer-name
) -> None:
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
		res = test_client.post("/rpc", auth=("01:02:aa:bb:cc:dd", "onet1mac"), json=rpc)
		assert res.status_code == 200
		assert res.json()

		test_client.reset_cookies()
		res = test_client.post("/rpc", auth=("01:02:aa:bb:cc:dd", "onet1mac"), json=rpc)
		assert res.status_code == 401
	finally:
		database_connection.query('DELETE FROM HOST WHERE hostId = "onetimepasswd.uib.gmbh"')
		database_connection.commit()


def test_auth_only_hostkey(
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
	database_connection: Connection,  # pylint: disable=redefined-outer-name,unused-argument
	config: Config,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:

	host_key = "f020dcde5108508cd947c5e229d9ec04"

	database_connection.query(
		"""
		INSERT INTO HOST
			(hostId, type, opsiHostKey)
		VALUES
			("onlyhostkey.uib.gmbh", "OpsiClient", "f020dcde5108508cd947c5e229d9ec04");
	"""
	)
	database_connection.commit()
	try:

		data = json.dumps({"id": 1, "jsonrpc": "2.0", "method": "host_getObjects", "params": [[], {"id": "onlyhostkey.uib.gmbh"}]})

		res = test_client.post("/rpc", auth=("", host_key), content=data)
		assert res.status_code == 401

		config.allow_host_key_only_auth = True

		res = test_client.post("/rpc", auth=(ADMIN_USER, host_key), content=data)
		assert res.status_code == 401

		res = test_client.post("/rpc", auth=("", ADMIN_PASS), content=data)
		assert res.status_code == 401

		res = test_client.post("/rpc", auth=("", host_key), content=data)
		assert res.status_code == 200

		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), content=data)
		assert res.status_code == 200

	finally:
		database_connection.query('DELETE FROM HOST WHERE hostId = "onlyhostkey.uib.gmbh"')
		database_connection.commit()


def test_auth_only_hostkey_id_header(
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
	database_connection: Connection,  # pylint: disable=redefined-outer-name,unused-argument
	config: Config,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:

	host_key = "f020dcde5108508cd947c5e229d9ec04"

	database_connection.query(
		"""
		INSERT INTO HOST
			(hostId, type, opsiHostKey)
		VALUES
			("onlyhostkey.uib.gmbh", "OpsiClient", "f020dcde5108508cd947c5e229d9ec04");
	"""
	)
	database_connection.commit()
	try:

		data = {"id": 1, "jsonrpc": "2.0", "method": "host_getObjects", "params": [[], {"id": "onlyhostkey.uib.gmbh"}]}

		config.allow_host_key_only_auth = True

		res = test_client.post("/rpc", auth=("", host_key), json=data)
		print(res.headers)
		assert res.status_code == 200
		assert res.headers["x-opsi-new-host-id"] == "onlyhostkey.uib.gmbh"
	finally:
		database_connection.query('DELETE FROM HOST WHERE hostId = "onlyhostkey.uib.gmbh"')
		database_connection.commit()
