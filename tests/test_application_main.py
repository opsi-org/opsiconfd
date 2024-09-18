# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test application.main
"""

import warnings
from datetime import datetime, timezone
from time import sleep
from unittest.mock import patch

from starlette.types import Receive, Scope, Send

from opsiconfd import __version__, contextvar_client_address
from opsiconfd.application.main import BaseMiddleware

from .utils import ADMIN_PASS, ADMIN_USER, OpsiconfdTestClient, clean_redis, get_config, test_client  # noqa: F401


def test_http_1_0_warning(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	orig_call = BaseMiddleware.__call__

	async def mock_call(self: BaseMiddleware, scope: Scope, receive: Receive, send: Send) -> None:
		scope["http_version"] = "1.0"
		return await orig_call(self, scope, receive, send)

	with patch("opsiconfd.application.main.BaseMiddleware.__call__", mock_call):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)

		with warnings.catch_warnings(record=True) as warns:
			test_client.get("/")
			assert len(warns) > 0
			for warn in warns:
				assert "is using http version 1.0" in str(warn.message)


def test_server_date_header(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.get("/")
	server_date = res.headers["date"]
	assert server_date.endswith(" UTC")
	server_dt = datetime.strptime(server_date, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
	now = datetime.now(tz=timezone.utc)
	assert abs((now - server_dt).total_seconds()) < 2

	server_timestamp = int(res.headers["x-date-unix-timestamp"])
	assert abs(now.timestamp() - server_timestamp) < 2

	sleep(1)

	res = test_client.get("/")
	server_date = res.headers["date"]
	server_dt = datetime.strptime(server_date, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
	assert now < server_dt


def test_server_headers(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with get_config({"saml-idp-sso-url": "https://keycloak.opsi.test/realms/master/protocol/saml"}):
		res = test_client.get("/login")
		assert res.status_code == 200
		assert res.headers["server"] == f"opsiconfd {__version__} (uvicorn)"
		assert res.headers["X-opsi-server-role"] == "configserver"
		assert res.headers["X-opsi-worker-id"] == "pytest:1"
		assert res.headers["X-opsi-auth-methods"] == "password,saml"


def test_trusted_proxy(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with get_config({"trusted_proxies": ["192.168.1.1/32", "192.168.2.1"]}):
		test_client.set_client_address("192.168.100.1", 12345)
		test_client.get("/")
		assert test_client.context and test_client.context.get(contextvar_client_address) == "192.168.100.1"

		test_client.get("/", headers={"x-forwarded-for": "192.168.200.1"})
		# x-forwarded-for must not be accepted
		assert test_client.context and test_client.context.get(contextvar_client_address) == "192.168.100.1"

		test_client.set_client_address("192.168.1.1", 12345)
		test_client.get("/", headers={"x-forwarded-for": "192.168.200.1"})
		# x-forwarded-for must be accepted from trusted proxy
		assert test_client.context and test_client.context.get(contextvar_client_address) == "192.168.200.1"

		test_client.set_client_address("192.168.2.1", 12345)
		test_client.get("/", headers={"x-forwarded-for": "192.168.200.2"})
		# x-forwarded-for must be accepted from trusted proxy
		assert test_client.context and test_client.context.get(contextvar_client_address) == "192.168.200.2"

	with get_config({"trusted_proxies": ["192.168.1.0/24"]}):
		test_client.set_client_address("192.168.1.1", 12345)
		test_client.get("/", headers={"x-forwarded-for": "192.168.200.1"})
		# x-forwarded-for must be accepted from trusted proxy
		assert test_client.context and test_client.context.get(contextvar_client_address) == "192.168.200.1"
