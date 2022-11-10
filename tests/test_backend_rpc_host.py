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
	Connection,
	OpsiconfdTestClient,
	database_connection,
	get_config,
	test_client,
)


@pytest.fixture(autouse=True)
def cleanup_database(database_connection: Connection) -> Generator[None, None, None]:  # pylint: disable=redefined-outer-name
	cursor = database_connection.cursor()
	cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test-backend-rpc-host%'")
	database_connection.commit()
	yield
	cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test-backend-rpc-host%'")
	database_connection.commit()
	cursor.close()


@pytest.fixture()
def acl_file(tmp_path: Path) -> Generator[Path, None, None]:
	_acl_file = tmp_path / "acl.conf"
	data = (
		f"host_getObjects   : sys_user({ADMIN_USER}); self; opsi_client(attributes(!opsiHostKey,!hardwareAddress,!inventoryNumber))\n"
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
		"id": "test-backend-rpc-host-insert-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-insert-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}
	# Create client 1
	rpc = {"id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	# Create client 2
	rpc = {"id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	# Client 1 should be created
	rpc = {"id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None
	client = res.json()["result"][0]
	for attr, val in client1.items():
		assert val == client[attr]

	# Update client 1 with null values
	client1["description"] = "new"
	client1["notes"] = ""
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	rpc = {"id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	# All values should be updated
	rpc = {"id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None
	client = res.json()["result"][0]
	for attr, val in client1.items():
		assert val == client[attr]

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])

	# Client can edit self
	client1["description"] = "client changed"
	rpc = {"id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	# Client has no permission to create or change other hosts
	client2["description"] = "client changed"
	rpc = {"id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"]["class"] == "BackendPermissionDeniedError"


def test_host_updateObject(  # pylint: disable=invalid-name
	acl_file: Path, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-update-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-update-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}
	# Call update
	rpc = {"id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	# Should not be created
	rpc = {"id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None
	client = res.json()["result"] == []

	# Create client 1
	rpc = {"id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	# Create client 2
	rpc = {"id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	# Update client 1
	client1["description"] = "new"
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	rpc = {"id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	# oneTimePassword should not be update because it is null
	# notes should not be update because not passed
	rpc = {"id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None
	client = res.json()["result"][0]
	assert client["description"] == client1["description"]
	assert client["notes"] == "notes"
	assert client["oneTimePassword"] == "secret"

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])
	client1["description"] = "client changed"
	rpc = {"id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"] is None

	client2["description"] = "client changed"
	rpc = {"id": 1, "method": "host_updateObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"]["class"] == "BackendPermissionDeniedError"
