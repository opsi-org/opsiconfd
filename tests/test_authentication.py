# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
login tests
"""

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pyotp
import pytest
from fastapi import status
from opsicommon import objects
from opsicommon.client.opsiservice import ServiceClient, ServiceVerificationFlags
from opsicommon.exceptions import OpsiServiceAuthenticationError
from opsicommon.logging import LOG_TRACE, use_logging_config

from opsiconfd import (
	contextvar_client_session,
	get_contextvars,
	set_contextvars,
	set_contextvars_from_contex,
)
from opsiconfd.redis import ip_address_to_redis_key, redis_client
from opsiconfd.session import OPSISession

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	MySQLConnection,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	config,
	database_connection,
	depot_jsonrpc,
	get_config,
	opsiconfd_server,
	test_client,
)


def test_get_session(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.get("/")
	cvars = get_contextvars()
	try:
		if test_client.context:
			set_contextvars_from_contex(test_client.context)
		assert contextvar_client_session.get()
	finally:
		set_contextvars(cvars)


@pytest.mark.parametrize(
	"auth_data, expected_status_code, expected_text",
	(
		(None, 401, "Authorization header missing"),
		(("", ""), 401, "Authentication error"),
		((ADMIN_USER, ""), 401, "Authentication error"),
		((ADMIN_USER, "123"), 401, "Authentication error"),
		(("", ADMIN_PASS), 401, "Authentication error"),
		(("123", ADMIN_PASS), 401, "Authentication error"),
	),
)
def test_login_error(
	test_client: OpsiconfdTestClient,  # noqa: F811
	auth_data: tuple[str, str],
	expected_status_code: int,
	expected_text: str,
) -> None:
	res = test_client.get("/auth/authenticated", auth=auth_data)
	assert res.status_code == expected_status_code
	assert res.text == expected_text
	assert res.headers.get("set-cookie", None) is not None


def test_x_opsi_user_id_header(
	test_client: OpsiconfdTestClient,  # noqa: F811
	database_connection: MySQLConnection,  # noqa: F811
) -> None:
	res = test_client.get("/auth/authenticated")
	assert res.status_code == 401
	assert res.headers.get("X-opsi-user-id", None) is None

	res = test_client.get("/auth/authenticated", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	assert res.headers.get("X-opsi-user-id", None) == f"user:{ADMIN_USER}"

	test_client.reset_cookies()

	res = test_client.get("/auth/authenticated")
	assert res.status_code == 401
	assert res.headers.get("X-opsi-user-id", None) is None

	with database_connection.session() as session:
		session.execute(
			"""
			INSERT INTO HOST
				(hostId, type, opsiHostKey)
			VALUES
				("client1.opsi.test", "OpsiClient", "08508cd947c5e22f020dcde519d9ec04");
		"""
		)

	try:
		res = test_client.get("/auth/authenticated", auth=("client1.opsi.test", "08508cd947c5e22f020dcde519d9ec04"))
		assert res.status_code == 200
		assert res.headers.get("X-opsi-user-id", None) == "client:client1.opsi.test"
	finally:
		with database_connection.session() as session:
			session.execute('DELETE FROM HOST WHERE hostId = "client1.opsi.test"')


def test_x_requested_with_header(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.get("/auth/authenticated")
	assert res.status_code == 401
	assert res.headers.get("www-authenticate", None) is not None

	res = test_client.get("/auth/authenticated", headers={"X-Requested-With": "XMLHttpRequest"})
	assert res.status_code == 401
	assert res.headers.get("www-authenticate", None) is None


def test_basic_auth(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	assert str(res.url).rstrip("/") in [f"{test_client.base_url}/admin", f"{test_client.base_url}/welcome"]


@pytest.mark.parametrize("base_path", ("/auth", "/session"))  # /session is deprecated
def test_login_endpoint(test_client: OpsiconfdTestClient, base_path: str) -> None:  # noqa: F811
	res = test_client.post(f"{base_path}/login", json={"username": ADMIN_USER, "password": "invalid"})
	assert res.status_code == 401
	assert "Authentication failed for user" in res.json()["message"]

	res = test_client.get(f"{base_path}/authenticated")
	assert res.status_code == 401

	res = test_client.get("/admin", follow_redirects=False)
	assert res.status_code == 307

	res = test_client.post(f"{base_path}/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
	assert res.json()["session_id"]
	assert res.status_code == 200

	res = test_client.get(f"{base_path}/authenticated")
	assert res.status_code == 200

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "user_getObjects", "params": [[], {"id": ADMIN_USER}]}
	res = test_client.post("/rpc", json=rpc)
	assert res.status_code == 200
	resp = res.json()
	assert "error" not in resp
	assert resp["result"][0]["id"] == ADMIN_USER
	diff = datetime.now() - datetime.strptime(resp["result"][0]["created"], "%Y-%m-%d %H:%M:%S")
	assert abs(diff.total_seconds()) < 5
	diff = datetime.now() - datetime.strptime(resp["result"][0]["lastLogin"], "%Y-%m-%d %H:%M:%S")
	assert abs(diff.total_seconds()) < 5


def test_logout_endpoint(config: Config, test_client: OpsiconfdTestClient) -> None:  # noqa: F811  # noqa: F811
	redis = redis_client()
	client_addr = "192.168.1.1"
	test_client.set_client_address(client_addr, 12345)

	res = test_client.get("/auth/authenticated", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200

	keys = sorted([key.decode() for key in redis.scan_iter(f"{config.redis_key('session')}:*")])
	assert len(keys) == 1
	assert keys[0].startswith(f"{config.redis_key('session')}:{ip_address_to_redis_key(client_addr)}:")

	res = test_client.get("/auth/logout")
	assert res.status_code == 200
	assert "opsiconfd-session" in res.headers["set-cookie"]
	assert "Max-Age=0" in res.headers["set-cookie"]
	keys = sorted([key.decode() for key in redis.scan_iter(f"{config.redis_key('session')}:*")])
	assert len(keys) == 0


def test_mfa_totp(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with get_config({"multi_factor_auth": "totp_mandatory"}):
		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		assert res.status_code == 401
		# Mandatory but no secret
		assert "MFA OTP configuration error" in res.json()["message"]

	with get_config({"multi_factor_auth": "totp_optional"}):
		test_client.reset_cookies()

		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		assert res.status_code == 200

		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "user_updateMultiFactorAuth",
			"params": {"userId": ADMIN_USER, "type": "totp", "returnType": "uri"},
		}
		res = test_client.post("/rpc", json=rpc)
		assert res.status_code == 200
		resp = res.json()
		assert "error" not in resp
		assert resp["result"]
		totp = pyotp.parse_uri(resp["result"])

		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		assert res.status_code == 401
		assert "MFA one-time password missing" in res.json()["message"]

		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS, "mfa_otp": "123456"})
		assert res.status_code == 401
		assert "Incorrect one-time password" in res.json()["message"]

		res = test_client.post(
			"/auth/login",
			json={"username": ADMIN_USER, "password": ADMIN_PASS, "mfa_otp": totp.now()},  # type: ignore[attr-defined]
		)
		assert res.status_code == 200
		# test session session.authenticated is true
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert "login?redirect" not in str(res.url)

	with get_config({"multi_factor_auth": "inactive"}):
		test_client.reset_cookies()

		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		assert res.status_code == 200

	with get_config({"multi_factor_auth": "totp_optional"}):
		test_client.reset_cookies()

		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		assert res.status_code == 401
		# test session session.authenticated is still false
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert "login?redirect" in str(res.url)

	with get_config({"multi_factor_auth": "inactive"}):
		test_client.reset_cookies()

		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		assert res.status_code == 200

		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "user_updateMultiFactorAuth",
			"params": {"userId": ADMIN_USER, "type": "inactive"},
		}
		res = test_client.post("/rpc", json=rpc)
		assert res.status_code == 200
		resp = res.json()
		assert "error" not in resp

	with get_config({"multi_factor_auth": "totp_optional"}):
		test_client.reset_cookies()

		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		assert res.status_code == 200


def test_change_session_ip(
	config: Config,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	redis = redis_client()
	client_addr = "192.168.1.1"
	test_client.set_client_address(client_addr, 12345)
	res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200

	keys = sorted([key.decode() for key in redis.scan_iter(f"{config.redis_key('session')}:*")])
	assert len(keys) == 1
	assert keys[0].startswith(f"{config.redis_key('session')}:{ip_address_to_redis_key(client_addr)}:")

	client_addr = "192.168.2.2"
	test_client.set_client_address(client_addr, 12345)
	res = test_client.get("/auth/authenticated")
	assert res.status_code == 401

	res = test_client.get("/auth/authenticated", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200

	keys = sorted([key.decode() for key in redis.scan_iter(f"{config.redis_key('session')}:*")])
	assert len(keys) == 2
	assert keys[1].startswith(f"{config.redis_key('session')}:{ip_address_to_redis_key(client_addr)}:")


def test_update_client_object(
	test_client: OpsiconfdTestClient,  # noqa: F811
	database_connection: MySQLConnection,  # noqa: F811
) -> None:
	host_id = "test-client-update.opsi.test"
	host_key = "0dc5e29e2994c04de5108508cdd7cf02"

	with database_connection.session() as session:
		session.execute(
			f"""
			INSERT INTO HOST
				(hostId, type, opsiHostKey, lastSeen, ipAddress)
			VALUES
				("{host_id}", "OpsiClient", "{host_key}", "2023-01-01 01:01:01", "1.2.3.4");
		"""
		)

	client_addr = "192.168.2.2"
	with get_config({"update-ip": True}):
		test_client.set_client_address(client_addr, 12345)
		res = test_client.post("/auth/login", json={"username": host_id, "password": host_key})
		assert res.status_code == 200

		with database_connection.session() as session:
			last_seen, ip_address = session.execute(f"SELECT lastSeen, ipAddress FROM HOST WHERE hostId = '{host_id}'").fetchone()
		delta = last_seen - datetime.now()
		assert abs(delta.total_seconds()) < 3
		assert ip_address == client_addr

		test_client.set_client_address("127.0.0.1", 12345)
		res = test_client.post("/auth/login", json={"username": host_id, "password": host_key})
		assert res.status_code == 200

		with database_connection.session() as session:
			last_seen, ip_address = session.execute(f"SELECT lastSeen, ipAddress FROM HOST WHERE hostId = '{host_id}'").fetchone()
		assert ip_address == client_addr

	with get_config({"update-ip": False}):
		test_client.set_client_address("4.3.2.1", 12345)
		res = test_client.post("/auth/login", json={"username": host_id, "password": host_key})
		assert res.status_code == 200

		with database_connection.session() as session:
			last_seen, ip_address = session.execute(f"SELECT lastSeen, ipAddress FROM HOST WHERE hostId = '{host_id}'").fetchone()
		assert ip_address == client_addr


def test_networks(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.set_client_address("1.2.3.4", 12345)
	with get_config({"networks": ["0.0.0.0/0"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

	with get_config({"networks": ["10.0.0.0/8"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 403


def test_admin_networks(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.set_client_address("1.2.3.4", 12345)
	with get_config({"networks": ["0.0.0.0/0"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

	with get_config({"networks": ["10.0.0.0/8"], "admin_networks": ["0.0.0.0/0"]}):
		res = test_client.get("/admin", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 403


def test_public_access_get(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.get("/public")
	assert res.status_code == 200


def test_public_access_put(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.put("/public/test.bin", content=b"test")
	assert res.status_code == 403


def test_max_sessions_limit(
	config: Config,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.set_client_address("192.168.1.1", 12345)
	max_session_per_ip = 10
	over_limit = 3
	redis_key = f"{config.redis_key('session')}:*"
	with get_config({"max_session_per_ip": max_session_per_ip}):
		for num in range(1, max_session_per_ip + 1 + over_limit):
			res = test_client.get("/admin/", auth=(ADMIN_USER, ADMIN_PASS))
			if num > max_session_per_ip:
				assert res.status_code == 403
				assert res.text.startswith("Too many sessions")
			else:
				assert res.status_code == 200
			test_client.reset_cookies()

		# Delete some sessions
		redis = redis_client()
		num = 0
		for key in redis.scan_iter(redis_key):
			num += 1
			redis.delete(key)
			if num > over_limit:
				break

		res = test_client.get("/admin/", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200


def test_max_sessions_not_for_depot(
	config: Config,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.set_client_address("192.168.11.1", 12345)
	max_session_per_ip = 3
	over_limit = 30
	redis_key = f"{config.redis_key('session')}:*"
	depot_id = "test-depot-max-sessions.uib.local"
	depot_key = "29124776768a560d5e45d3c50889ec51"
	with depot_jsonrpc(test_client, "", depot_id, depot_key):
		test_client.reset_cookies()
		with get_config({"max_session_per_ip": max_session_per_ip}):
			for _ in range(1, max_session_per_ip + 1 + over_limit):
				res = test_client.get("/depot", auth=(depot_id, depot_key))
				assert res.status_code == 200
				test_client.reset_cookies()

		redis = redis_client()
		session_keys = list(redis.scan_iter(redis_key))
		assert len(session_keys) >= max_session_per_ip + over_limit

		# Delete sessions
		for key in session_keys:
			redis.delete(key)


@pytest.mark.parametrize(
	"url, method",
	(
		(
			"/auth/authenticated",
			"get",
		),
		(
			"/auth/login",
			"post",
		),
	),
)
@pytest.mark.flaky(retries=1, delay=1)
def test_max_auth_failures(
	config: Config,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
	url: str,
	method: str,
) -> None:
	over_limit = 3
	max_auth_failures = 5
	with get_config({"max_auth_failures": max_auth_failures}) as conf:
		for num in range(max_auth_failures + over_limit):
			now = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
			print("now:", now, ", num:", num, ", max_auth_failures:", max_auth_failures)
			redis = redis_client()
			for key in redis.scan_iter(f"{config.redis_key('stats')}:client:failed_auth:*"):
				cmd = (
					f"ts.range {key.decode()} "
					f"{(now-(conf.auth_failures_interval*1000))} {now} aggregation count {(conf.auth_failures_interval*1000)}"
				)
				num_failed_auth = redis.execute_command(cmd)
				num_failed_auth = int(num_failed_auth[-1][1]) if num_failed_auth else -1
				print("key:", key, ", num_failed_auth:", num_failed_auth)

			# if num == max_auth_failures:
			# 	time.sleep(2)
			if method == "get":
				res = test_client.get(url, auth=("client.domain.tld", "hostkey"))
				if num > max_auth_failures + 2:
					assert res.status_code == status.HTTP_403_FORBIDDEN
					assert "blocked" in res.text
				elif max_auth_failures + 1 <= num <= max_auth_failures + 2:
					assert res.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)
				else:
					assert res.status_code == status.HTTP_401_UNAUTHORIZED
					assert res.text == "Authentication error"
			else:
				res = test_client.post("/auth/login", json={"username": "adminuser", "password": "false"})
				assert res.status_code == status.HTTP_401_UNAUTHORIZED
				body = res.json()
				if num > max_auth_failures + 1:
					assert body["class"] == "ConnectionRefusedError"
					assert body["status"] == status.HTTP_401_UNAUTHORIZED
					assert "blocked" in body["message"]
				elif num == max_auth_failures + 1:
					assert res.status_code == status.HTTP_401_UNAUTHORIZED
				else:
					assert res.status_code == status.HTTP_401_UNAUTHORIZED
					assert body["class"] == "OpsiServiceAuthenticationError"
					assert body["status"] == status.HTTP_401_UNAUTHORIZED

			print("Auth:", num, max_auth_failures, res.status_code, res.text)


def test_session_expire(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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
		res = test_client.get("/auth/authenticated")
		assert res.status_code == 200
		cookie = list(test_client.cookies.jar)[0]
		assert session_id == cookie.value

	# Let session expire
	time.sleep(lifetime + 1)
	res = test_client.get("/auth/authenticated")
	assert res.status_code == 401


def test_session_max_age(test_client: OpsiconfdTestClient, config: Config) -> None:  # noqa: F811  # noqa: F811
	with patch("opsiconfd.session.MESSAGEBUS_IN_USE_TIMEOUT", 15):
		lifetime = config.session_lifetime
		test_client.auth = (ADMIN_USER, ADMIN_PASS)

		res = test_client.get("/admin/")
		assert res.status_code == 200
		cookie = list(test_client.cookies.jar)[0]
		session_id = cookie.value
		remain = cookie.expires - time.time()  # type: ignore[operator]
		print(remain)
		assert remain <= lifetime

		lifetime = 60 * 15  # 15 min
		lt_headers = {"x-opsi-session-lifetime": str(lifetime)}
		res = test_client.get("/admin/", headers=lt_headers)
		assert res.status_code == 200
		cookie = list(test_client.cookies.jar)[0]
		remain = cookie.expires - time.time()  # type: ignore[operator]
		print(remain)
		assert remain <= lifetime
		assert remain >= lifetime - 5
		assert session_id == cookie.value

		print("Connect to messagebus")
		with test_client.websocket_connect("/messagebus/v1", headers={"Cookie": f"{cookie.name}={cookie.value}"}):
			res = test_client.get("/admin/", headers=lt_headers)
			assert res.status_code == 200
			cookie = list(test_client.cookies.jar)[0]
			# If session is used my messagebus, session expires never
			assert cookie.expires is None

		# Messagebus no longer connected, wait for MESSAGEBUS_IN_USE_TIMEOUT + 1
		time.sleep(16)
		res = test_client.get("/admin/")
		assert res.status_code == 200
		cookie = list(test_client.cookies.jar)[0]
		remain = cookie.expires - time.time()  # type: ignore[operator]
		print(remain)
		assert remain <= lifetime
		assert remain >= lifetime - 5
		assert session_id == cookie.value


def test_onetime_password_host_id(
	test_client: OpsiconfdTestClient,  # noqa: F811
	database_connection: MySQLConnection,  # noqa: F811
) -> None:
	with database_connection.session() as session:
		session.execute(
			"""
			INSERT INTO HOST
				(hostId, type, opsiHostKey, oneTimePassword)
			VALUES
				("onetimepasswd.opsi.test", "OpsiClient", "f020dcde5108508cd947c5e229d9ec04", "onet1me");
		"""
		)

	try:
		rpc = {"id": 1, "method": "backend_info", "params": []}
		res = test_client.post("/rpc", auth=("onetimepasswd.opsi.test", "onet1me"), json=rpc)
		assert res.status_code == 200
		assert res.json()
		assert test_client.context
		sess = test_client.context.get(contextvar_client_session)
		assert sess and sess.auth_methods == {"host_id", "password_onetime"}

		assert (
			session.execute(
				"""
			SELECT oneTimePassword FROM HOST where hostId = "onetimepasswd.opsi.test"
			"""
			).fetchone()[0]
			== ""
		)

		test_client.reset_cookies()
		res = test_client.post("/rpc", auth=("onetimepasswd.opsi.test", "onet1me"), json=rpc)
		assert res.status_code == 401
	finally:
		with database_connection.session() as session:
			session.execute('DELETE FROM HOST WHERE hostId = "onetimepasswd.opsi.test"')


def test_auth_system_uuid_hardware_address_and_hostkey(
	test_client: OpsiconfdTestClient,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	opsi_client = objects.OpsiClient(
		id="onlyhostkey.opsi.test",
		opsiHostKey="f020dcde5108508cd947c5e229d9ec04",
		systemUUID="69bdfe1a-55df-4392-95ab-85715cd0e77e",
		hardwareAddress="aa:bb:aa:bb:cc:dd",
	)
	assert opsi_client.opsiHostKey
	backend.host_createObjects([opsi_client])

	rpc = {"id": 1, "jsonrpc": "2.0", "method": "host_getObjects", "params": [[], {"id": opsi_client.id}]}

	res = test_client.post("/rpc", auth=("{system_uuid}" + (opsi_client.systemUUID or ""), opsi_client.opsiHostKey), json=rpc)
	assert res.status_code == 200
	test_client.reset_cookies()
	assert test_client.context
	sess = test_client.context.get(contextvar_client_session)
	assert sess and sess.auth_methods == {"system_uuid", "host_key"}

	test_client.reset_cookies()

	res = test_client.post("/rpc", auth=("{hardware_address}" + (opsi_client.hardwareAddress or ""), opsi_client.opsiHostKey), json=rpc)
	assert res.status_code == 200
	test_client.reset_cookies()
	assert test_client.context
	sess = test_client.context.get(contextvar_client_session)
	assert sess and sess.auth_methods == {"hardware_address", "host_key"}


def test_onetime_password_hardware_address(
	test_client: OpsiconfdTestClient,  # noqa: F811
	database_connection: MySQLConnection,  # noqa: F811
) -> None:
	with database_connection.session() as session:
		session.execute(
			"""
			INSERT INTO HOST
				(hostId, type, opsiHostKey, oneTimePassword, hardwareAddress)
			VALUES
				("onetimepasswd.opsi.test", "OpsiClient", "f020dcde5108508cd947c5e229d9ec04", "onet1mac", "01:02:aa:bb:cc:dd");
		"""
		)
	try:
		rpc = {"id": 1, "method": "backend_info", "params": []}
		res = test_client.post("/rpc", auth=("01:02:aa:bb:cc:dd", "onet1mac"), json=rpc)
		assert res.status_code == 200
		assert res.json()
		assert test_client.context
		sess = test_client.context.get(contextvar_client_session)
		assert sess and sess.auth_methods == {"hardware_address", "password_onetime"}

		test_client.reset_cookies()
		res = test_client.post("/rpc", auth=("01:02:aa:bb:cc:dd", "onet1mac"), json=rpc)
		assert res.status_code == 401
	finally:
		with database_connection.session() as session:
			session.execute('DELETE FROM HOST WHERE hostId = "onetimepasswd.opsi.test"')


def test_auth_only_hostkey(
	test_client: OpsiconfdTestClient,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	opsi_client = objects.OpsiClient(id="onlyhostkey.opsi.test", opsiHostKey="f020dcde5108508cd947c5e229d9ec04")
	assert opsi_client.opsiHostKey
	backend.host_createObjects([opsi_client])

	rpc = {"id": 1, "jsonrpc": "2.0", "method": "host_getObjects", "params": [[], {"id": opsi_client.id}]}

	with get_config({"allow_host_key_only_auth": False}):
		res = test_client.post("/rpc", auth=("", opsi_client.opsiHostKey), json=rpc)
		assert res.status_code == 401
		test_client.reset_cookies()

	with get_config({"allow_host_key_only_auth": True}):
		res = test_client.post("/rpc", auth=(ADMIN_USER, opsi_client.opsiHostKey), json=rpc)
		assert res.status_code == 401
		test_client.reset_cookies()

		res = test_client.post("/rpc", auth=("", ADMIN_PASS), json=rpc)
		assert res.status_code == 401
		test_client.reset_cookies()

		res = test_client.post("/rpc", auth=("", opsi_client.opsiHostKey), json=rpc)
		assert res.status_code == 200
		assert res.headers["x-opsi-new-host-id"] == opsi_client.id
		test_client.reset_cookies()
		assert test_client.context
		sess = test_client.context.get(contextvar_client_session)
		assert sess and sess.auth_methods == {"host_key"}

		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
		assert res.status_code == 200


test_urls = (
	(
		"/auth/authenticated",
		"get",
	),
	(
		"/auth/login",
		"post",
	),
)


@pytest.mark.parametrize(
	"min_configed_version, user_agent, status_code, response_text_match",
	(
		(None, "opsiclientd 4.1.0.0", 200, ""),
		("4.3.0.0", "opsiclientd 4.1.0.0", 200, ""),
		("4.3.0.0", None, 200, ""),
		(None, "opsi config editor 4.2.0.0", 200, ""),
		("4.3.0.1", "opsi config editor 4.3.0.1", 200, ""),
		("4.3.0.1", "opsi config editor 4.3.1.0", 200, ""),
		("4.3.0.1", "opsi config editor 4.4.0.0", 200, ""),
		("4.3.0.0", "opsi config editor 4.2.0.0", 426, "Configed 4.2.0.0 is not allowed to connect (min-configed-version: 4.3.0.0)"),
	),
)
def test_min_configed_version(
	test_client: OpsiconfdTestClient,  # noqa: F811
	min_configed_version: str | None,
	user_agent: str | None,
	status_code: int,
	response_text_match: str,
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with get_config({"min_configed_version": min_configed_version}):
		if user_agent:
			res = test_client.get("/admin/", headers={"User-Agent": str(user_agent)})
		else:
			res = test_client.get("/admin/")
		assert res.status_code == status_code
		assert response_text_match in res.text


def test_client_certificate(
	tmp_path: Path,
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	client_cert_file = tmp_path / "client-cert.pem"
	opsi_client = objects.OpsiClient(id="client1.opsi.test", opsiHostKey="cde58508cc5e229d9ec04d94710f020d")
	backend.host_createObjects([opsi_client])
	sess = OPSISession("localhost")
	sess.is_admin = True
	contextvar_client_session_org = contextvar_client_session.get()
	contextvar_client_session.set(sess)
	try:
		with opsiconfd_server({"client_cert_auth": ["client"]}) as server_conf:
			pem = backend.host_getTLSCertificate(opsi_client.id)
			client_cert_file.write_text(pem, encoding="utf-8")

			with use_logging_config(stderr_level=LOG_TRACE):
				with ServiceClient(
					address=f"https://localhost:{server_conf.port}",
					username=opsi_client.id,
					password=opsi_client.opsiHostKey,
					verify=ServiceVerificationFlags.ACCEPT_ALL,
				) as client:
					with pytest.raises(OpsiServiceAuthenticationError):
						assert client.jsonrpc("accessControl_authenticated")
					with pytest.raises(OpsiServiceAuthenticationError):
						client.messagebus.connect()

				with ServiceClient(
					address=f"https://localhost:{server_conf.port}",
					username=opsi_client.id,
					password=opsi_client.opsiHostKey,
					verify=ServiceVerificationFlags.ACCEPT_ALL,
					client_cert_file=client_cert_file,
				) as client:
					assert client.jsonrpc("accessControl_authenticated")
					# Delete session and connect messagebus without valid cookie
					# so that the client has to authenticate again with the client certificate
					client.get("/auth/logout")
					client.messagebus.connect()
					assert client.messagebus.jsonrpc("accessControl_authenticated")
	finally:
		contextvar_client_session.set(contextvar_client_session_org)


def test_recover_clients(test_client: OpsiconfdTestClient, backend: UnprotectedBackend) -> None:  # noqa: F811
	res = test_client.post(
		"/rpc",
		headers={"User-Agent": "opsiclientd/4.3.1.1"},
		auth=("testclient.uib.gmbh", "08508cd947c5e22f020dcde519d9ec04"),
		json={"id": 1, "method": "host_getIdents", "params": []},
	)
	print(res.text)
	assert res.status_code == 401
	with get_config({"recover-clients": True}):
		res = test_client.post(
			"/rpc",
			headers={"User-Agent": "opsiclientd/4.3.1.1"},
			auth=("testclient.uib.gmbh", "08508cd947c5e22f020dcde519d9ec04"),
			json={"id": 1, "method": "host_getIdents", "params": []},
		)
		print(res.text)
		res.status_code == 200
		clients = backend.host_getObjects(id="testclient.uib.gmbh")
		assert len(clients) == 1
		client = clients[0]
		assert client.id == "testclient.uib.gmbh"
		assert client.opsiHostKey == "08508cd947c5e22f020dcde519d9ec04"
		assert client.notes == "Created by opsiconfd with recover clients option."
		backend.host_deleteObjects([client])


@pytest.mark.parametrize("test_timeout", (True, False))
def test_authenticated_wait_time(test_client: OpsiconfdTestClient, test_timeout: bool) -> None:  # noqa: F811
	res = test_client.get("/auth/session_id")
	assert res.status_code == 200
	session_id = res.json()
	assert session_id
	assert session_id in res.headers.get("set-cookie", "")
	cookie = list(test_client.cookies.jar)[0]
	assert cookie.value == session_id

	res = test_client.get("/auth/wait_authenticated")
	assert res.status_code == 401
	assert res.json() is False
	assert session_id in res.headers.get("set-cookie", "")
	cookie = list(test_client.cookies.jar)[0]
	assert cookie.value == session_id

	authenticated_result: bool | None = None

	def wait_auth_thread() -> None:
		nonlocal authenticated_result
		res = test_client.post("/auth/wait_authenticated", json={"wait_time": 3 if test_timeout else 20})
		if res.status_code == 200:
			authenticated_result = res.json()
		else:
			authenticated_result = False

	threading.Thread(target=wait_auth_thread, daemon=True).start()
	time.sleep(5)

	if test_timeout:
		# /auth/authenticated must have returned False
		assert authenticated_result is False
	else:
		# /auth/authenticated must be bocking
		assert authenticated_result is None

		res = test_client.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		assert res.status_code == 200
		time.sleep(2)
		# /auth/authenticated must have returned True
		assert authenticated_result is True
