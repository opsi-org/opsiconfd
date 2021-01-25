
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
import requests
import urllib3

BASE_URL = "https://localhost:4447"
USERNAME = "adminuser"
PASSWORD = "adminuser"

def test_webdav_upload_download_delete():
	urllib3.disable_warnings()

	size = 1*1024*1024
	rand_bytes = bytearray(random.getrandbits(8) for _ in range(size))
	headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}

	url = f"{BASE_URL}/repository/test_file.bin"
	res = requests.put(url=url, verify=False, auth=(USERNAME, PASSWORD), headers=headers, data=rand_bytes)
	res.raise_for_status()

	url = f"{BASE_URL}/repository/test_file.bin"
	res = requests.get(url=url, verify=False, auth=(USERNAME, PASSWORD))
	res.raise_for_status()
	assert rand_bytes == res.content

	url = f"{BASE_URL}/repository/test_file.bin"
	res = requests.delete(url=url, verify=False, auth=(USERNAME, PASSWORD))
	res.raise_for_status()

def test_webdav_auth():
	urllib3.disable_warnings()

	url = f"{BASE_URL}/repository/test_file.bin"
	res = requests.get(url=url, verify=False)

	assert res.status_code == 401

