# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav tests
"""

import random
import requests

from .utils import (  # pylint: disable=unused-import
	disable_request_warning, config, ADMIN_USER, ADMIN_PASS
)


def test_webdav_upload_download_delete(config):  # pylint: disable=redefined-outer-name
	size = 1*1024*1024
	rand_bytes = bytearray(random.getrandbits(8) for _ in range(size))
	headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}

	url = f"{config.external_url}/repository/test_file.bin"
	res = requests.put(url=url, verify=False, auth=(ADMIN_USER, ADMIN_PASS), headers=headers, data=rand_bytes)
	res.raise_for_status()

	res = requests.get(url=url, verify=False, auth=(ADMIN_USER, ADMIN_PASS))
	res.raise_for_status()
	assert rand_bytes == res.content

	res = requests.delete(url=url, verify=False, auth=(ADMIN_USER, ADMIN_PASS))
	res.raise_for_status()

def test_webdav_auth(config):  # pylint: disable=redefined-outer-name
	url = f"{config.external_url}/repository/test_file.bin"
	res = requests.get(url=url, verify=False)
	assert res.status_code == 401

def test_client_permission(config):  # pylint: disable=redefined-outer-name
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
	res = admin_session.post(f"{config.external_url}/rpc", verify=False, json=rpc)
	assert res.status_code == 200
	res = res.json()
	assert res.get("error") is None

	client_session = requests.Session()
	client_session.auth = (client_id, client_key)

	size = 1024
	data = bytearray(random.getrandbits(8) for _ in range(size))
	headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}
	for path in ("workbench", "repository", "depot"):
		url = f"{config.external_url}/{path}/test_file_client.bin"

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

		admin_session.post(url=f"{config.external_url}/admin/unblock-all", verify=False)

	rpc = {
		"id": 1,
		"method": "host_delete",
		"params": [
			client_id
		]
	}
	res = admin_session.post(f"{config.external_url}/rpc", verify=False, json=rpc)
	assert res.status_code == 200
