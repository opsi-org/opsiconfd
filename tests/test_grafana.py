# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
grafana tests
"""

import asyncio
import json
import shutil
import time
from configparser import RawConfigParser
from pathlib import Path
from unittest.mock import patch

import pytest
from opsicommon.testing.helpers import HTTPTestServer, http_test_server

from opsiconfd.grafana import async_grafana_admin_session, create_dashboard_user, grafana_admin_session, set_grafana_root_url

from .utils import get_config


@pytest.mark.parametrize("filename", ("tests/data/grafana/faulty.ini", "tests/data/grafana/defaults.ini", "tests/data/grafana/sample.ini"))
def test_set_grafana_root_url(tmp_path: Path, filename: str) -> None:
	grafana_ini = tmp_path / "grafana.ini"
	grafana_ini_orig = Path(filename)
	shutil.copy(grafana_ini_orig, grafana_ini)
	with patch("opsiconfd.grafana.GRAFANA_INI", str(grafana_ini)):
		time.sleep(1)
		mtime = grafana_ini.stat().st_mtime
		set_grafana_root_url()
		assert abs(grafana_ini.stat().st_size - grafana_ini_orig.stat().st_size) < 60
		assert mtime != grafana_ini.stat().st_mtime

		# Call again, no changes needed
		mtime = grafana_ini.stat().st_mtime
		set_grafana_root_url()
		assert mtime == grafana_ini.stat().st_mtime

	new = grafana_ini.read_text(encoding="utf-8")
	new_config = RawConfigParser()
	new_config.read_string("[DEFAULT]\n" + new)
	assert new_config["server"]["root_url"] == r"%(protocol)s://%(domain)s:%(http_port)s/grafana"
	for section in new_config:
		if section == "server":
			continue
		assert "root_url" not in new_config[section]


def test_grafana_admin_session(tmp_path: Path) -> None:
	log_file = tmp_path / "request.log"
	with http_test_server(log_file=log_file) as server:
		with get_config({"grafana_internal_url": f"http://apikey@localhost:{server.port}/"}):
			with grafana_admin_session() as (base_url, session):
				res = session.get(f"{base_url}/")
				assert res.status_code == 200
	log = log_file.read_text(encoding="utf-8")
	request = json.loads(log)
	# print(request)
	assert request["headers"]["authorization"] == "Bearer apikey"


async def test_async_grafana_admin_session(tmp_path: Path) -> None:
	log_file = tmp_path / "request.log"
	with http_test_server(log_file=log_file) as server:
		with get_config({"grafana_internal_url": f"http://apikey@localhost:{server.port}/"}):
			async with async_grafana_admin_session() as (base_url, session):
				res = await session.get(f"{base_url}/")
				assert res.status == 200
	log = log_file.read_text(encoding="utf-8")
	request = json.loads(log)
	# print(request)
	assert request["headers"]["Authorization"] == "Bearer apikey"


async def test_create_dashboard_user() -> None:
	requests = []

	def request_callback(server: HTTPTestServer, request: dict) -> None:
		nonlocal requests
		requests.append(request)
		# print(request)
		if len(requests) == 1:
			server.response_status = (200, "OK")
			server.response_body = json.dumps({"message": "user created"}).encode("utf-8")
		elif len(requests) == 2:
			server.response_status = (200, "OK")
			server.response_body = json.dumps(
				{
					"id": 11,
					"name": "opsidashboard",
					"login": "opsidashboard",
					"email": "opsidashboard@admin",
				}
			).encode("utf-8")
		elif len(requests) == 3:
			server.response_status = (200, "OK")
			server.response_body = json.dumps({"message": "user updated"}).encode("utf-8")

	with http_test_server(request_callback=request_callback, response_headers={"Content-Type": "application/json"}) as server:
		with get_config({"grafana_internal_url": f"http://apikey@localhost:{server.port}/"}):
			# User does not exist
			server.response_status = (404, "Not found")
			server.response_body = json.dumps({"message": "user not found"}).encode("utf-8")

			username, password = await create_dashboard_user()
			assert username == "opsidashboard"

			for _ in range(10):
				if len(requests) == 2:
					break
				await asyncio.sleep(1)
			assert len(requests) == 2

			assert requests[0]["method"] == "GET"
			assert requests[0]["headers"]["Authorization"] == "Bearer apikey"
			assert requests[0]["path"] == "/api/users/lookup?loginOrEmail=opsidashboard"

			assert requests[1]["method"] == "POST"
			assert requests[1]["headers"]["Authorization"] == "Bearer apikey"
			assert requests[1]["path"] == "/api/admin/users"
			assert requests[1]["request"]["name"] == "opsidashboard"
			assert requests[1]["request"]["email"] == "opsidashboard@admin"
			assert requests[1]["request"]["login"] == "opsidashboard"
			assert requests[1]["request"]["password"] == password

			# Call again, user already exists
			new_username, new_password = await create_dashboard_user()

			for _ in range(10):
				if len(requests) == 4:
					break
				await asyncio.sleep(1)
			assert len(requests) == 4

			assert requests[2]["method"] == "GET"
			assert requests[2]["headers"]["Authorization"] == "Bearer apikey"
			assert requests[2]["path"] == "/api/users/lookup?loginOrEmail=opsidashboard"

			assert requests[3]["method"] == "PUT"
			assert requests[3]["headers"]["Authorization"] == "Bearer apikey"
			assert requests[3]["path"] == "/api/admin/users/11/password"

			assert new_username == username
			assert new_password != password
