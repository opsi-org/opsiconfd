
# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""

import random
from aiohttp.client import request
import requests
import urllib3

BASE_URL = "https://localhost:4447"
ADMIN_USER = "adminuser"
ADMIN_PASS = "adminuser"

def test_webdav_upload_download_delete():
	urllib3.disable_warnings()

	size = 1*1024*1024
	rand_bytes = bytearray(random.getrandbits(8) for _ in range(size))
	headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}

	url = f"{BASE_URL}/repository/test_file.bin"
	res = requests.put(url=url, verify=False, auth=(ADMIN_USER, ADMIN_PASS), headers=headers, data=rand_bytes)
	res.raise_for_status()

	res = requests.get(url=url, verify=False, auth=(ADMIN_USER, ADMIN_PASS))
	res.raise_for_status()
	assert rand_bytes == res.content

	res = requests.delete(url=url, verify=False, auth=(ADMIN_USER, ADMIN_PASS))
	res.raise_for_status()

def test_webdav_auth():
	urllib3.disable_warnings()

	url = f"{BASE_URL}/repository/test_file.bin"
	res = requests.get(url=url, verify=False)
	assert res.status_code == 401

def test_client_permission():
	urllib3.disable_warnings()

	admin_session = requests.Session()
	admin_session.auth = (ADMIN_USER, ADMIN_PASS)

	client_id = "webdavtest.uib.local"
	client_key = "af521906af3c4666bed30a1774639ff8"
	rpc = {
		"id": 1,
		"method": "host_createOpsiClient",
		"params": [
			client_id,
			client_key
		]
	}
	res = admin_session.post(f"{BASE_URL}/rpc", verify=False, json=rpc)
	assert res.status_code == 200
	res = res.json()
	assert res.get("error") is None

	client_session = requests.Session()
	client_session.auth = (client_id, client_key)

	size = 1024
	data = bytearray(random.getrandbits(8) for _ in range(size))
	headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}
	for path in ("workbench", "repository", "depot"):
		url = f"{BASE_URL}/{path}/test_file_client.bin"

		res = admin_session.put(url=url, verify=False, data=data, headers=headers)
		assert res.status_code in (201, 204)

		res = client_session.put(url=url, verify=False)
		assert res.status_code == 401

		res = client_session.get(url=url, verify=False)
		assert res.status_code == 200 if path == "depot" else 401

		res = client_session.delete(url=url, verify=False)
		assert res.status_code == 401

		res = admin_session.delete(url=url, verify=False)
		assert res.status_code == 204

		admin_session.post(url=f"{BASE_URL}/admin/unblock-all", verify=False)
