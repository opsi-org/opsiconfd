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
from uuid import uuid4

import pytest

from opsiconfd.backend.rpc.main import ProtectedBackend
from tests.utils import (  # pylint: disable=unused-import
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
		f"host_getObjects    : sys_user({ADMIN_USER}); self; opsi_client(attributes(!opsiHostKey,!hardwareAddress,!inventoryNumber))\n"
		f"host_insertObject  : sys_user({ADMIN_USER}); self\n"
		f"host_updateObject  : sys_user({ADMIN_USER}); self\n"
		f"host_deleteObjects : sys_user({ADMIN_USER}); self\n"
		f".*                 : sys_user({ADMIN_USER})\n"
	)
	_acl_file.write_text(data=data, encoding="utf-8")
	backend = ProtectedBackend()
	try:
		with get_config({"acl_file": str(_acl_file)}):
			backend._read_acl_file()  # pylint: disable=protected-access
		yield _acl_file
	finally:
		# Restore original ACL
		backend._read_acl_file()  # pylint: disable=protected-access


def test_host_insertObject(  # pylint: disable=invalid-name
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
		"systemUUID": str(uuid4()),
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}
	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create client 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Client 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	for attr, val in client1.items():
		assert val == client[attr]

	# Update client 1 with null values
	client1["description"] = "new"
	client1["notes"] = ""
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# All values should be updated
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	for attr, val in client1.items():
		assert val == client[attr]

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])

	# Client can edit self
	client1["description"] = "client changed"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Client has no permission to create or change other hosts
	client2["description"] = "client changed"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert res["error"]["data"]["class"] == "OpsiServicePermissionError"


def test_host_updateObject(  # pylint: disable=invalid-name
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}
	# Call update
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Should not be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"] == []

	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create client 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Update client 1
	client1["description"] = "new"
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# oneTimePassword should not be update because it is null
	# notes should not be update because not passed
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["description"] == client1["description"]
	assert client["notes"] == "notes"
	assert client["oneTimePassword"] == "secret"

	# Test update without type
	client1_upd = {
		"id": "test-backend-rpc-host-1.opsi.test",
		"description": "without type",
	}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1_upd]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["description"] == client1_upd["description"]
	assert client["type"] == "OpsiClient"

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])
	client1["description"] = "client changed"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	client2["description"] = "client changed"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert res["error"]["data"]["class"] == "OpsiServicePermissionError"


def test_host_createObjects(  # pylint: disable=invalid-name,too-many-statements
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}

	# Create clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	clients = res["result"]

	assert len(clients) == 2
	assert clients[0]["id"].startswith("test-backend-rpc-host-")
	assert clients[1]["id"].startswith("test-backend-rpc-host-")
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
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	clients = res["result"]
	assert len(clients) == 2

	assert clients[0]["id"].startswith("test-backend-rpc-host-")
	assert clients[1]["id"].startswith("test-backend-rpc-host-")
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
	res = test_client.post("/rpc", json=rpc).json()
	assert res["error"]["data"]["class"] == "OpsiServicePermissionError"

	for method in ("host_getObjects", "host_getHashes"):
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": method,
			"params": [None, {"id": [client1["id"], client2["id"]]}],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		clients = res["result"]
		assert len(clients) == 2
		for client in clients:
			if client["id"] == client1["id"]:
				assert client["opsiHostKey"] == client1["opsiHostKey"]
			else:
				assert client["opsiHostKey"] is None


def test_host_updateObjects(  # pylint: disable=invalid-name,too-many-statements
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}

	# Create clients with updateObjects
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	clients = res["result"]

	assert len(clients) == 2
	assert clients[0]["id"].startswith("test-backend-rpc-host-")
	assert clients[1]["id"].startswith("test-backend-rpc-host-")
	assert clients[0]["oneTimePassword"] == "secret"
	assert clients[1]["oneTimePassword"] == "secret"

	# Delete client2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_deleteObjects", "params": [[{"id": client2["id"]}]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	clients = res["result"]

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	clients = res["result"]
	assert len(clients) == 1

	# Update client1, create client2
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	client1["description"] = "new desc"
	client2["oneTimePassword"] = None  # type: ignore[assignment]
	client2["description"] = "new desc"

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	clients = res["result"]
	assert len(clients) == 2

	for client in clients:
		assert client["description"] == "new desc"
		if client["id"] == client1["id"]:
			# Updated
			assert client["oneTimePassword"] == "secret"
		else:
			# Created
			assert client["oneTimePassword"] is None

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObjects", "params": [[client1]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObjects", "params": [[client2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert res["error"]["data"]["class"] == "OpsiServicePermissionError"


def test_host_getIdents(  # pylint: disable=invalid-name,too-many-statements
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}

	# Create clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Get client idents
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getIdents", "params": ["dict", {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == [{"id": "test-backend-rpc-host-1.opsi.test"}, {"id": "test-backend-rpc-host-2.opsi.test"}]

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getIdents", "params": ["dict", {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == [{"id": "test-backend-rpc-host-1.opsi.test"}]

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getIdents", "params": ["dict", {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == [{"id": "test-backend-rpc-host-1.opsi.test"}, {"id": "test-backend-rpc-host-2.opsi.test"}]


def test_host_deleteObjects(  # pylint: disable=invalid-name,too-many-statements
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
	}

	# Create clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])

	# Should only delete client1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_deleteObjects", "params": [[{"id": client1["id"]}, {"id": client2["id"]}]]}
	res = test_client.post("/rpc", json=rpc).json()

	# Get client idents
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getIdents", "params": ["list", {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == [[client2["id"]]]

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_deleteObjects", "params": [[{"id": client2["id"]}]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert res["error"]["data"]["class"] == "OpsiServicePermissionError"

	# Delete clients
	test_client.reset_cookies()
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_deleteObjects", "params": [[{"id": client1["id"]}, {"id": client2["id"]}]]}
	res = test_client.post("/rpc", json=rpc).json()

	# Get client idents
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getIdents", "params": ["list", {"id": [client1["id"], client2["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	result = res["result"]
	assert len(result) == 0

	# Create clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Delete client1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_delete", "params": [client1["id"]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getIdents", "params": ["dict", {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert res["result"] == []


def test_host_createOpsiClient(  # pylint: disable=invalid-name,too-many-statements
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	# Create client
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_createOpsiClient",
		"params": ["test-backend-rpc-host-client.opsi.test", None, "description", "notes", "00:00:00:01:01:01", None, "inventory number"],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_getObjects",
		"params": [None, {"type": "OpsiClient", "id": "test-backend-rpc-host-client.opsi.test"}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["opsiHostKey"]
	assert client["created"]
	assert client["hardwareAddress"] == "00:00:00:01:01:01"
	assert client["notes"] == "notes"

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_getObjects",
		"params": [["description", "notes"], {"id": "test-backend-rpc-host-client.opsi.test"}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert not client["opsiHostKey"]
	assert not client["created"]
	assert not client["hardwareAddress"]
	assert client["description"] == "description"
	assert client["notes"] == "notes"


def test_host_createOpsiDepotserver(  # pylint: disable=invalid-name,too-many-statements
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	# Create depot
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_createOpsiDepotserver",
		"params": ["test-backend-rpc-host-depot.opsi.test", None, "file:///depot/local/url", "webdavs://depot.remote/url"],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_getObjects",
		"params": [None, {"type": "OpsiDepotserver", "id": "test-backend-rpc-host-depot.opsi.test"}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	depot = res["result"][0]
	assert depot["opsiHostKey"]
	assert depot["depotLocalUrl"] == "file:///depot/local/url"
	assert depot["depotRemoteUrl"] == "webdavs://depot.remote/url"


def test_host_createOpsiConfigserver(  # pylint: disable=invalid-name,too-many-statements
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	# Create depot
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_createOpsiConfigserver",
		"params": ["test-backend-rpc-host-server.opsi.test", None, "file:///depot/local/url", "webdavs://depot.remote/url"],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_getObjects",
		"params": [None, {"type": "OpsiConfigserver", "id": "test-backend-rpc-host-server.opsi.test"}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	depot = res["result"][0]
	assert depot["opsiHostKey"]
	assert depot["depotLocalUrl"] == "file:///depot/local/url"
	assert depot["depotRemoteUrl"] == "webdavs://depot.remote/url"


def test_host_check_duplicate_hardware_address(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	# Create client
	rpc1 = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_createOpsiClient",
		"params": {"id": "test-backend-rpc-client1.opsi.test", "hardwareAddress": "01:02:03:04:05:06"},
	}
	res = test_client.post("/rpc", json=rpc1).json()
	assert "error" not in res

	rpc2 = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_createOpsiClient",
		"params": {"id": "test-backend-rpc-client2.opsi.test", "hardwareAddress": "01:02:03:04:05:06"},
	}
	res = test_client.post("/rpc", json=rpc2).json()
	assert "error" in res
	assert res["error"]["message"] == "Hardware address '01:02:03:04:05:06' is already used by host 'test-backend-rpc-client1.opsi.test'"

	res = test_client.post("/rpc", json=rpc1).json()
	assert "error" not in res
