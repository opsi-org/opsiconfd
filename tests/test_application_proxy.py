# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.proxy
"""

import json

import pytest
from opsicommon.testing.helpers import http_test_server

from opsiconfd.application import app
from opsiconfd.application.proxy import ReverseProxy

from .utils import ADMIN_PASS, ADMIN_USER, test_client  # pylint: disable=unused-import


def test_reverse_proxy_request(tmp_path, test_client):  # pylint: disable=redefined-outer-name
	log_file = tmp_path / "request.log"

	with http_test_server(log_file=log_file) as server:
		ReverseProxy(app, "/test_reverse_proxy", f"http://localhost:{server.port}")

		res = test_client.get("/test_reverse_proxy/test/get", auth=(ADMIN_USER, ADMIN_PASS))
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

		ReverseProxy(app, "/test_reverse_proxy2", f"http://localhost:{server.port}", forward_authorization=True)

		res = test_client.get("/test_reverse_proxy2/test/get", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

		log = log_file.read_text(encoding="utf-8")
		request = json.loads(log)

		assert "authorization" in request["headers"]
