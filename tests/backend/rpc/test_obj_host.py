# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd.backend.mysql
"""

import json
from pathlib import Path
from typing import Generator
from uuid import uuid4

import pytest
from opsicommon.objects import (
	AuditSoftware,
	AuditSoftwareOnClient,
	BoolConfig,
	ConfigState,
	HostGroup,
	LicenseContract,
	LicenseOnClient,
	LicensePool,
	LocalbootProduct,
	ObjectToGroup,
	OpsiClient,
	OpsiDepotserver,
	ProductOnClient,
	ProductPropertyState,
	RetailSoftwareLicense,
	SoftwareLicenseToLicensePool,
	UnicodeProductProperty,
	deserialize,
)

from opsiconfd.backend.rpc.main import ProtectedBackend
from opsiconfd.backend.rpc.obj_host import auto_fill_depotserver_urls
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	get_config,
	test_client,
)


@pytest.fixture()
def acl_file(tmp_path: Path) -> Generator[Path, None, None]:
	_acl_file = tmp_path / "acl.conf"
	data = (
		f"host_getObjects    : sys_user({ADMIN_USER}); opsi_depotserver; self; opsi_client(attributes(!opsiHostKey,!hardwareAddress,!inventoryNumber))\n"
		f"host_insertObject  : sys_user({ADMIN_USER}); self\n"
		f"host_updateObject  : sys_user({ADMIN_USER}); self\n"
		f"host_deleteObjects : sys_user({ADMIN_USER}); self\n"
		f".*_get.*           : sys_group({ADMIN_USER}); opsi_depotserver; opsi_client\n"
		f".*                 : sys_user({ADMIN_USER})\n"
	)
	_acl_file.write_text(data=data, encoding="utf-8")
	backend = ProtectedBackend()
	try:
		with get_config({"acl_file": str(_acl_file)}):
			backend._read_acl_file()
		yield _acl_file
	finally:
		# Restore original ACL
		backend._read_acl_file()


def test_auto_fill_depotserver_url() -> None:
	depot = OpsiDepotserver(id="depot.opsi.test", workbenchRemoteUrl="smb://172.16.1.1/opsi_workbench")
	assert auto_fill_depotserver_urls(depot)
	assert depot.depotLocalUrl == "file:///var/lib/opsi/depot"
	assert depot.depotRemoteUrl == "smb://depot.opsi.test/opsi_depot"
	assert depot.depotWebdavUrl == "webdavs://depot.opsi.test:4447/depot"
	assert depot.repositoryLocalUrl == "file:///var/lib/opsi/repository"
	assert depot.repositoryRemoteUrl == "smb://depot.opsi.test/opsi_repository"
	assert depot.workbenchLocalUrl == "file:///var/lib/opsi/workbench"
	assert depot.workbenchRemoteUrl == "smb://172.16.1.1/opsi_workbench"
	# assert no changes
	assert not auto_fill_depotserver_urls(depot)


def test_host_insertObject(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_host_updateObject(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_host_updateObject_systemUUID(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"" "description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
		"systemUUID": "9f3f1c96-1821-413c-b850-0507a17c7e47",
	}

	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Update client 1
	client1["description"] = "new"
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	client1["systemUUID"] = ""
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# oneTimePassword should not be update because it is null
	# notes should not be update because not passed
	# systemUUID should be null
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["description"] == client1["description"]
	assert client["notes"] == "notes"
	assert client["oneTimePassword"] == "secret"
	assert client["systemUUID"] is None

	# Update client 1
	client1["systemUUID"] = "9f3f1c96-1821-413c-b850-0507a17c7e47"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# systemUUID should be "9f3f1c96-1821-413c-b850-0507a17c7e47"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["systemUUID"] == "9f3f1c96-1821-413c-b850-0507a17c7e47"

	# Update client 1
	client1["systemUUID"] = None  # type: ignore[assignment]
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# systemUUID should be "9f3f1c96-1821-413c-b850-0507a17c7e47"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["systemUUID"] == "9f3f1c96-1821-413c-b850-0507a17c7e47"


def test_host_updateObject_ip_mac(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"ipAddress": "192.168.36.1",
		"hardwareAddress": "aa:ff:ee:aa:ff:ee",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
		"systemUUID": "9f3f1c96-1821-413c-b850-0507a17c7e47",
	}

	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Update client 1
	client1["description"] = "new"
	client1["oneTimePassword"] = None  # type: ignore[assignment]
	client1["hardwareAddress"] = ""
	client1["ipAddress"] = ""
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# oneTimePassword should not be update because it is null
	# notes should not be update because not passed
	# hardwareAddress should be null
	# ipAddress should be null
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["description"] == client1["description"]
	assert client["notes"] == "notes"
	assert client["oneTimePassword"] == "secret"
	assert client["hardwareAddress"] is None
	assert client["ipAddress"] is None

	# Update client 1
	client1["ipAddress"] = "192.168.36.1"
	client1["hardwareAddress"] = "aa:ff:ee:aa:ff:ee"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# ipAddress should be "192.168.36.1"
	# hardwareAddress should be "aa:ff:ee:aa:ff:ee"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["ipAddress"] == "192.168.36.1"
	assert client["hardwareAddress"] == "aa:ff:ee:aa:ff:ee"

	# Update client 1
	client1["hardwareAddress"] = None  # type: ignore[assignment]
	client1["ipAddress"] = None  # type: ignore[assignment]
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObject", "params": [client1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# ipAddress should be "192.168.36.1"
	# hardwareAddress should be "aa:ff:ee:aa:ff:ee"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": client1["id"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	client = res["result"][0]
	assert client["ipAddress"] == "192.168.36.1"
	assert client["hardwareAddress"] == "aa:ff:ee:aa:ff:ee"


@pytest.mark.filterwarnings("ignore:.*calling deprecated method.*")
def test_host_createObjects(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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

		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": method,
			"params": [None, {"inventoryNumber": ["123*"]}],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "No permission for attribute inventoryNumber" in res["error"]["message"]


def test_host_createObjects_with_systemUUID(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
		"systemUUID": "",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
		"systemUUID": "",
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
	assert clients[0]["systemUUID"] is None
	assert clients[1]["systemUUID"] is None

	client3 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-3.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
		"systemUUID": "9f3f1c96-1821-413c-b850-0507a17c7e47",
	}

	# Create client3
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client3]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client3["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	clients = res["result"]

	assert len(clients) == 1
	assert clients[0]["id"] == "test-backend-rpc-host-3.opsi.test"
	assert clients[0]["systemUUID"] == "9f3f1c96-1821-413c-b850-0507a17c7e47"

	client4 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-4.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
		"systemUUID": None,
	}

	# Create client4
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client4]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Get clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [None, {"id": [client4["id"]]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	clients = res["result"]

	assert len(clients) == 1
	assert clients[0]["id"] == "test-backend-rpc-host-4.opsi.test"
	assert clients[0]["systemUUID"] is None


def test_host_updateObjects(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_host_getObjects(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
		"inventoryNumber": "host-1",
	}
	client2 = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-2.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924e",
		"description": "description",
		"oneTimePassword": "secret",
		"inventoryNumber": "host-2",
	}
	depot1 = {
		"type": "OpsiDepotserver",
		"id": "test-backend-rpc-host-3.opsi.test",
		"opsiHostKey": "3d58924c50167a2ec547de0976855861",
		"description": "description",
		"oneTimePassword": "secret",
		"inventoryNumber": "host-3",
	}

	# Create hosts
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2, depot1]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Get host objects
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": []}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert len(res["result"]) == 4
	for host in res["result"]:
		assert host["id"]
		assert host["opsiHostKey"]
		if host["id"] in (client1["id"], client2["id"], depot1["id"]):
			assert host["inventoryNumber"]

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1["id"], client1["opsiHostKey"])

	# Get host objects
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": []}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert len(res["result"]) == 4
	for host in res["result"]:
		if host["id"] == client1["id"]:
			# ACL self
			assert host["opsiHostKey"]
			assert host["inventoryNumber"]
		else:
			# ACL opsi_client
			assert not host["opsiHostKey"]
			assert not host["inventoryNumber"]

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_getObjects", "params": [[], {"opsiHostKey": client2["opsiHostKey"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" in res
	assert res["error"]["data"]["class"] == "OpsiServicePermissionError"
	assert res["error"]["message"] == "Opsi service permission error: No permission for attribute opsiHostKey"


def test_host_getIdents(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_host_deleteObjects(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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
	group1 = {
		"type": "HostGroup",
		"id": "test-backend-rpc-host-group-1",
		"description": "description",
	}
	object_to_group1 = {
		"groupType": "HostGroup",
		"groupId": "test-backend-rpc-host-group-1",
		"objectId": "test-backend-rpc-host-1.opsi.test",
	}
	object_to_group2 = {
		"groupType": "HostGroup",
		"groupId": "test-backend-rpc-host-group-1",
		"objectId": "test-backend-rpc-host-2.opsi.test",
	}

	# Create clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client1, client2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create group
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "group_createObjects", "params": [[group1]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create ObjectToGroup
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "objectToGroup_createObjects", "params": [[object_to_group1, object_to_group2]]}
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

	# Get ObjectToGroup idents
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "objectToGroup_getIdents", "params": ["dict", {"objectId": [client1["id"], client2["id"]]}]}
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


def test_host_createOpsiClient(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_host_createOpsiDepotserver(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_host_createOpsiConfigserver(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def test_host_check_duplicate_hardware_address(
	test_client: OpsiconfdTestClient,  # noqa: F811
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


def _create_clients_and_depot(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> tuple(list[dict[str, str], dict[str, str]]):  # type: ignore[valid-type]
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	clients = [
		{
			"type": "OpsiClient",
			"id": "test-backend-rpc-host-1.opsi.test",
			"opsiHostKey": "4587dec5913c501a28560d576768924e",
			"description": "description",
			"notes": "notes",
		},
		{
			"type": "OpsiClient",
			"id": "test-backend-rpc-host-2.opsi.test",
			"opsiHostKey": "7dec5913c501a28545860d576768924a",
			"description": "description",
		},
	]

	depot = {
		"type": "OpsiDepotserver",
		"id": "opsi.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924f",
		"description": "description",
		"repositoryRemoteUrl": "smb://opsi.opsi.test:4447/repository",
		"workbenchRemoteUrl": "smb://opsi:4447/opsi_workbench",
		"depotRemoteUrl": "smb://opsi.opsi.test:4447/opsi_depot",
		"depotWebdavUrl": "webdavs://opsi.opsi.test:4447/depot",
	}

	# Create clients
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[clients[0], clients[1], depot]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Assign client 2 to depot
	client_to_depot = {"configId": "clientconfig.depot.id", "objectId": clients[1]["id"], "values": [depot["id"]]}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_create", "params": client_to_depot}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	return (clients, depot)


def test_rename_depot(test_client: OpsiconfdTestClient, clean_mysql: Generator) -> None:  # noqa: F811  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	# create clients and depot. client 2 is assigned to depot
	clients, depot = _create_clients_and_depot(test_client)

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "configState_getObjects",
		"params": [[], {"objectId": [clients[0]["id"], clients[1]["id"]], "configId": "clientconfig.depot.id"}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][0]["values"][0] == depot["id"]

	# renmame depot, new config state should exist, client 2 should use value from depot
	new_depot_id = "opsi01.opsi.test"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_renameOpsiDepotserver", "params": [depot["id"], new_depot_id]}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "configState_getObjects",
		"params": [[], {"objectId": [clients[0]["id"], clients[1]["id"]], "configId": "clientconfig.depot.id"}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert len(res["result"]) == 1
	assert res["result"][0]["values"][0] == new_depot_id

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "host_getObjects",
		"params": [[], {"id": new_depot_id}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)

	assert len(res["result"]) == 1
	depot = res["result"][0]
	assert depot["id"] == new_depot_id
	assert depot["repositoryRemoteUrl"] == f"smb://{new_depot_id}:4447/repository"
	assert depot["depotRemoteUrl"] == f"smb://{new_depot_id}:4447/opsi_depot"
	assert depot["depotWebdavUrl"] == f"webdavs://{new_depot_id}:4447/depot"
	# workbench url only contains hostname
	assert depot["workbenchRemoteUrl"] == f"smb://{new_depot_id.split('.', maxsplit=1)[0]}:4447/opsi_workbench"


def test_rename_client(test_client: OpsiconfdTestClient, clean_mysql: Generator) -> None:  # noqa: F811  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	client = OpsiClient(id="test-rename-client.opsi.test")
	group = HostGroup(id="client-group")
	product = LocalbootProduct(id="product1", productVersion="1.0", packageVersion="1")
	product_property = UnicodeProductProperty(
		productId=product.id,
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		propertyId="property1",
		possibleValues=["v1", "v2", "v3"],
	)
	config = BoolConfig(id="config1")
	config_state = ConfigState(configId=config.id, objectId=client.id, values=[True])
	object_to_group = ObjectToGroup(groupType=group.getType(), groupId=group.id, objectId=client.id)
	product_on_client = ProductOnClient(
		productId=product.id, productType=product.getType(), clientId=client.id, installationStatus="installed"
	)
	product_property_state = ProductPropertyState(
		productId=product.id, propertyId=product_property.propertyId, objectId=client.id, values=["v1", "v2"]
	)
	audit_software = AuditSoftware(name="audit1", version="1.0", subVersion="1", language="", architecture="")
	audit_software_on_client = AuditSoftwareOnClient(
		name="audit1", version="1.0", subVersion="1", language="", architecture="", clientId=client.id
	)
	hwaudit = Path("tests/data/hwaudit/hwaudit.json").read_text(encoding="utf-8")
	audit_hardware_on_hosts = deserialize(json.loads(hwaudit.replace("{{host_id}}", client.id)))
	license_pool = LicensePool(id="pool1")
	license_contract = LicenseContract(id="contract1")
	software_license = RetailSoftwareLicense(id="lic1", licenseContractId=license_contract.id, boundToHost=client.id)
	software_license_to_license_pool = SoftwareLicenseToLicensePool(softwareLicenseId=software_license.id, licensePoolId=license_pool.id)
	license_on_client = LicenseOnClient(softwareLicenseId=software_license.id, licensePoolId=license_pool.id, clientId=client.id)

	assert "error" not in test_client.jsonrpc20(method="host_createObjects", params=[[client]])
	assert "error" not in test_client.jsonrpc20(method="group_createObjects", params=[[group]])
	assert "error" not in test_client.jsonrpc20(method="product_createObjects", params=[[product]])
	assert "error" not in test_client.jsonrpc20(method="productProperty_createObjects", params=[[product_property]])
	assert "error" not in test_client.jsonrpc20(method="config_createObjects", params=[[config]])
	assert "error" not in test_client.jsonrpc20(method="configState_createObjects", params=[[config_state]])
	assert "error" not in test_client.jsonrpc20(method="objectToGroup_createObjects", params=[[object_to_group]])
	assert "error" not in test_client.jsonrpc20(method="productOnClient_createObjects", params=[[product_on_client]])
	assert "error" not in test_client.jsonrpc20(method="productPropertyState_createObjects", params=[[product_property_state]])
	assert "error" not in test_client.jsonrpc20(method="auditSoftware_createObjects", params=[[audit_software]])
	assert "error" not in test_client.jsonrpc20(method="auditSoftwareOnClient_createObjects", params=[[audit_software_on_client]])
	assert "error" not in test_client.jsonrpc20(method="auditHardwareOnHost_createObjects", params=[audit_hardware_on_hosts])
	assert "error" not in test_client.jsonrpc20(method="licensePool_createObjects", params=[license_pool])
	assert "error" not in test_client.jsonrpc20(method="licenseContract_createObjects", params=[license_contract])
	assert "error" not in test_client.jsonrpc20(method="softwareLicense_createObjects", params=[software_license])
	assert "error" not in test_client.jsonrpc20(
		method="softwareLicenseToLicensePool_createObjects", params=[software_license_to_license_pool]
	)
	assert "error" not in test_client.jsonrpc20(method="licenseOnClient_createObjects", params=[license_on_client])

	client_ids = test_client.jsonrpc20(method="host_getIdents", params=["str", {"type": "OpsiClient"}])["result"]
	assert client_ids == [client.id]

	result = test_client.jsonrpc20(method="objectToGroup_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].objectId == client.id

	result = test_client.jsonrpc20(method="configState_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].objectId == client.id

	result = test_client.jsonrpc20(method="productOnClient_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].clientId == client.id

	result = test_client.jsonrpc20(method="productPropertyState_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].objectId == client.id

	result = test_client.jsonrpc20(method="auditSoftwareOnClient_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].clientId == client.id

	result = test_client.jsonrpc20(method="auditHardwareOnHost_getObjects", params=[])["result"]
	assert len(result) == len(audit_hardware_on_hosts)
	assert result[0].hostId == client.id

	result = test_client.jsonrpc20(method="licenseOnClient_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].clientId == client.id

	result = test_client.jsonrpc20(method="softwareLicense_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].boundToHost == client.id

	# Rename
	new_client_id = "test-rename-client-new.opsi.test"
	assert "error" not in test_client.jsonrpc20(method="host_renameOpsiClient", params=[client.id, new_client_id])

	client_ids = test_client.jsonrpc20(method="host_getIdents", params=["str", {"type": "OpsiClient"}])["result"]
	assert client_ids == [new_client_id]

	result = test_client.jsonrpc20(method="objectToGroup_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].objectId == new_client_id

	result = test_client.jsonrpc20(method="configState_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].objectId == new_client_id

	result = test_client.jsonrpc20(method="productOnClient_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].clientId == new_client_id

	result = test_client.jsonrpc20(method="productPropertyState_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].objectId == new_client_id

	result = test_client.jsonrpc20(method="auditSoftwareOnClient_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].clientId == new_client_id

	result = test_client.jsonrpc20(method="auditHardwareOnHost_getObjects", params=[])["result"]
	assert len(result) == len(audit_hardware_on_hosts)
	assert result[0].hostId == new_client_id

	result = test_client.jsonrpc20(method="licenseOnClient_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].clientId == new_client_id

	result = test_client.jsonrpc20(method="softwareLicense_getObjects", params=[])["result"]
	assert len(result) == 1
	assert result[0].boundToHost == new_client_id
