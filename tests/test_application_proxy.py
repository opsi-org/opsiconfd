# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test application.proxy
"""

import json
import time
from pathlib import Path
from urllib.parse import urlparse

import mock  # type: ignore[import]
from opsicommon.testing.helpers import http_test_server  # type: ignore[import]

from opsiconfd.application import app
from opsiconfd.application.proxy import ReverseProxy

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	WebSocketMessageReader,
	config,
	get_config,
	test_client,
)


def test_reverse_proxy_request(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	log_file = tmp_path / "request.log"

	with (
		mock.patch("opsiconfd.application.proxy.proxy_logger.isEnabledFor", lambda lvl: True),
		http_test_server(log_file=str(log_file)) as server,
	):
		ReverseProxy(app, "/test_reverse_proxy_request1", f"http://localhost:{server.port}")

		res = test_client.get("/test_reverse_proxy_request1/test/get", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

		log = log_file.read_text(encoding="utf-8")
		request = json.loads(log)

		assert request["method"] == "GET"
		assert request["headers"]["x-forwarded-proto"] == "https"
		assert request["headers"]["x-forwarded-host"] == request["headers"]["x-forwarded-server"]
		assert request["headers"]["x-forwarded-for"] == request["headers"]["x-real-ip"] == "127.0.0.1"
		assert "cookie" not in request["headers"]
		assert "authorization" not in request["headers"]

		log_file.unlink()

		ReverseProxy(app, "/test_reverse_proxy_request2", f"http://localhost:{server.port}", forward_authorization=True)

		res = test_client.get("/test_reverse_proxy_request2/test/get", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

		log = log_file.read_text(encoding="utf-8")
		request = json.loads(log)

		assert "authorization" in request["headers"]


def test_forward_cookie(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	log_file = tmp_path / "request.log"

	with http_test_server(log_file=str(log_file)) as server:
		ReverseProxy(app, "/test_forward_cookie1", f"http://localhost:{server.port}", forward_cookies=None)

		headers = {"Cookie": "test-cookie=123"}
		res = test_client.get("/test_forward_cookie1/test/get", auth=(ADMIN_USER, ADMIN_PASS), headers=headers)
		assert res.status_code == 200

		log = log_file.read_text(encoding="utf-8")
		request = json.loads(log)

		assert request["method"] == "GET"
		assert "cookie" not in request["headers"]

		log_file.unlink()

		ReverseProxy(app, "/test_forward_cookie2", f"http://localhost:{server.port}", forward_cookies=["test-cookie1", "test-cookie2"])

		headers = {"Cookie": "test-cookie1=123"}
		res = test_client.get("/test_forward_cookie2/test/get", auth=(ADMIN_USER, ADMIN_PASS), headers=headers)
		assert res.status_code == 200

		headers = {"Cookie": "test-cookie2=abc"}
		res = test_client.get("/test_forward_cookie2/test/get", auth=(ADMIN_USER, ADMIN_PASS), headers=headers)
		assert res.status_code == 200

		headers = {"Cookie": "test-cookie3=abc"}
		res = test_client.get("/test_forward_cookie2/test/get", auth=(ADMIN_USER, ADMIN_PASS), headers=headers)
		assert res.status_code == 200

		requests = [json.loads(line) for line in log_file.read_text(encoding="utf-8").strip().split("\n")]
		assert requests[0]["headers"]["cookie"] == "test-cookie1=123"
		assert requests[1]["headers"]["cookie"] == "test-cookie2=abc"
		assert "cookie" not in requests[2]["headers"]
		log_file.unlink()

		ReverseProxy(app, "/test_forward_cookie3", f"http://localhost:{server.port}", forward_cookies=["*"])

		headers = {"Cookie": "test-cookie3=abc"}
		res = test_client.get("/test_forward_cookie3/test/get", auth=(ADMIN_USER, ADMIN_PASS), headers=headers)
		assert res.status_code == 200

		headers = {"Cookie": "opsiconfd-session=secret"}
		res = test_client.get("/test_forward_cookie3/test/get", auth=(ADMIN_USER, ADMIN_PASS), headers=headers)
		assert res.status_code == 200

		requests = [json.loads(line) for line in log_file.read_text(encoding="utf-8").strip().split("\n")]
		assert requests[0]["headers"]["cookie"] == "test-cookie3=abc"
		assert "cookie" not in requests[1]["headers"]
		log_file.unlink()


def test_invalid_path(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with http_test_server() as server:
		proxy = ReverseProxy(app, "/test_invalid_path", f"http://localhost:{server.port}")
		proxy.base_url = f"http://localhost:{server.port}/test/base"
		res = test_client.get("/test_invalid_path/test", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 404


def test_bad_gateway(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	ReverseProxy(app, "/test_bad_gateway", "http://localhost:1")
	res = test_client.get("/test_bad_gateway/test", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 502


def test_websocket(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	log_file = tmp_path / "request.log"
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with http_test_server(log_file=str(log_file)) as server:
		ReverseProxy(app, "/test_websocket", f"http://localhost:{server.port}")
		with test_client.websocket_connect("/test_websocket/path/to/ws") as websocket:
			# TODO: Implement websocket server in http_test_server
			with WebSocketMessageReader(websocket):
				time.sleep(1)

	log = log_file.read_text(encoding="utf-8")
	request = json.loads(log)
	assert request["method"] == "GET"
	assert request["headers"]["Connection"] == "upgrade"
	assert request["headers"]["Sec-WebSocket-Key"]
	assert request["headers"]["Upgrade"] == "websocket"
	assert request["headers"]["x-forwarded-host"] == "testserver"
	assert request["headers"]["x-forwarded-server"] == "testserver"
	assert request["headers"]["x-forwarded-for"] == request["headers"]["x-real-ip"]


def test_grafana_reverse_proxy(test_client: OpsiconfdTestClient, config: Config) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client as client:
		client.auth = (ADMIN_USER, ADMIN_PASS)

		grafana_internal_url = urlparse(config.grafana_internal_url)
		print(grafana_internal_url)

		res = client.post("/grafana/login", json={"user": grafana_internal_url.username, "password": grafana_internal_url.password})
		print(res.json())
		assert res.status_code == 200
		assert res.json()["message"] == "Logged in"

		assert client.cookies.get("grafana_session") is not None
		assert client.cookies.get("grafana_session_expiry") is not None

		res = client.get("/grafana/api/dashboards/home")

		assert res.status_code == 200
