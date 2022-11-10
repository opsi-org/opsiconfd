# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.mysql
"""

from pathlib import Path
from typing import Generator

import pytest

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	get_config,
	test_client,
)


@pytest.fixture()
def acl_file(tmp_path: Path) -> Generator[Path, None, None]:
	_acl_file = tmp_path / "acl.conf"
	data = (
		f"host_getObjects   : sys_user({ADMIN_USER}); self\n"
		f"host_insertObject : sys_user({ADMIN_USER}); self\n"
		f"host_updateObject : sys_user({ADMIN_USER}); self\n"
		f".*                : sys_user({ADMIN_USER})\n"
	)
	_acl_file.write_text(data=data, encoding="utf-8")
	with get_config({"acl_file": str(_acl_file)}):
		yield _acl_file


def test_host_insertObject(  # pylint: disable=invalid-name
	acl_file: Path, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-client1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-client2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}
	rpc = {"id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	rpc = {"id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	rpc = {"id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None
	client = res.json()["result"][0]
	for attr, val in client1.items():
		assert val == client[attr]

	client1["description"] = "new"
	client1["notes"] = ""
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	rpc = {"id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	rpc = {"id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None
	client = res.json()["result"][0]
	for attr, val in client1.items():
		assert val == client[attr]

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])
	client1["description"] = "client changed"
	rpc = {"id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	client2["description"] = "client changed"
	rpc = {"id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"]["class"] == "BackendPermissionDeniedError"
