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
	clean_redis,
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
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# Create client 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# Client 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()
	client = res.json()["result"][0]
	for attr, val in client1.items():
		assert val == client[attr]

	# Update client 1 with null values
	client1["description"] = "new"
	client1["notes"] = ""
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# All values should be updated
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()
	client = res.json()["result"][0]
	for attr, val in client1.items():
		assert val == client[attr]

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])

	# Client can edit self
	client1["description"] = "client changed"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# Client has no permission to create or change other hosts
	client2["description"] = "client changed"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"]["data"]["class"] == "BackendPermissionDeniedError"


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
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# Should not be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()
	client = res.json()["result"] == []

	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# Create client 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# Update client 1
	client1["description"] = "new"
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# oneTimePassword should not be update because it is null
	# notes should not be update because not passed
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()
	client = res.json()["result"][0]
	assert client["description"] == client1["description"]
	assert client["notes"] == "notes"
	assert client["oneTimePassword"] == "secret"

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])
	client1["description"] = "client changed"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	client2["description"] = "client changed"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"]["data"]["class"] == "BackendPermissionDeniedError"


def test_host_createObjects(  # pylint: disable=invalid-name,too-many-statements
	acl_file: Path, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-create-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-create-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}

	# Create clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()
	clients = res.json()["result"]

	assert len(clients) == 2
	assert clients[0]["id"].startswith("test-backend-rpc-host-create")
	assert clients[1]["id"].startswith("test-backend-rpc-host-create")
	assert clients[0]["oneTimePassword"] == "secret"
	assert clients[1]["oneTimePassword"] == "secret"

	# Recreate clients
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	client1["notes"] = ""
	del client1["description"]
	client2["oneTimePassword"] = None  # type: ignore[assignment]
	client2["notes"] = ""
	del client2["description"]

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()
	clients = res.json()["result"]
	assert len(clients) == 2

	assert clients[0]["id"].startswith("test-backend-rpc-host-create")
	assert clients[1]["id"].startswith("test-backend-rpc-host-create")
	assert clients[0]["oneTimePassword"] is None
	assert clients[1]["oneTimePassword"] is None
	assert clients[0]["notes"] == ""
	assert clients[1]["notes"] == ""
	assert clients[0]["description"] == ""
	assert clients[1]["description"] == ""

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc)
	assert res.json()["error"]["data"]["class"] == "BackendPermissionDeniedError"

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc)
	assert "error" not in res.json()
	clients = res.json()["result"]
	assert len(clients) == 2
	for client in clients:
		if client["id"] == client1["id"]:  # pylint: disable=loop-invariant-statement
			assert client["opsiHostKey"] == client1["opsiHostKey"]  # pylint: disable=loop-invariant-statement
		else:
			assert client["opsiHostKey"] is None
