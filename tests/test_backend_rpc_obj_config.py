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
from opsicommon.objects import OpsiClient, UnicodeConfig  # type: ignore[import]

from opsiconfd.backend.rpc.opsiconfd import OpsiconfdBackend

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
	cursor.execute("DELETE FROM `CONFIG_VALUE` WHERE configId LIKE 'test-backend-rpc-obj-config%'")
	cursor.execute("DELETE FROM `CONFIG` WHERE configId LIKE 'test-backend-rpc-obj-config%'")
	cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test-backend-rpc-obj-config%'")
	database_connection.commit()
	yield
	cursor.execute("DELETE FROM `CONFIG_VALUE` WHERE configId LIKE 'test-backend-rpc-obj-config%'")
	cursor.execute("DELETE FROM `CONFIG` WHERE configId LIKE 'test-backend-rpc-obj-config%'")
	cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test-backend-rpc-obj-config%'")
	database_connection.commit()
	cursor.close()


@pytest.fixture()
def acl_file(tmp_path: Path) -> Generator[Path, None, None]:
	_acl_file = tmp_path / "acl.conf"
	data = (
		f"config_getObjects    : sys_user({ADMIN_USER}); opsi_depotserver; opsi_client\n"
		f"config_insertObject  : sys_user({ADMIN_USER}); opsi_depotserver\n"
		f"config_updateObject  : sys_user({ADMIN_USER}); opsi_depotserver\n"
		f"config_deleteObjects : sys_user({ADMIN_USER}); opsi_depotserver\n"
		f".*                   : sys_user({ADMIN_USER}); opsi_depotserver\n"
	)
	_acl_file.write_text(data=data, encoding="utf-8")
	with get_config({"acl_file": str(_acl_file)}):
		OpsiconfdBackend().read_acl_file()
		yield _acl_file


def test_config_insertObject(  # pylint: disable=invalid-name
	acl_file: Path, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = OpsiClient(id="test-backend-rpc-obj-config-1.opsi.test", opsiHostKey="c68857de49124e5860d3c501a2675795")
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	config1 = UnicodeConfig(
		id="test-backend-rpc-obj-config-1", possibleValues=["1", "2", "3"], defaultValues=["1", "2"], editable=True, multiValue=True
	)
	config2 = UnicodeConfig(
		id="test-backend-rpc-obj-config-2", possibleValues=["1", "2", "3"], defaultValues=None, editable=False, multiValue=False
	)

	# Create config1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_insertObject", "params": [config1.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create config2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_insertObject", "params": [config2.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_getObjects", "params": [None, {"id": [config1.id, config2.id]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert len(res["result"]) == 2
	config = res["result"][0]
	del config["ident"]
	assert config == config1.to_hash()
	config = res["result"][1]
	del config["ident"]
	assert config == config2.to_hash()

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1.id, client1.opsiHostKey)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_insertObject", "params": [config1.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert res["error"]["data"]["class"] == "BackendPermissionDeniedError"


def test_config_updateObject(  # pylint: disable=invalid-name
	acl_file: Path, test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = OpsiClient(id="test-backend-rpc-obj-config-1.opsi.test", opsiHostKey="c68857de49124e5860d3c501a2675795")
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client1.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	config1 = UnicodeConfig(
		id="test-backend-rpc-obj-config-1", possibleValues=["a", "b", "c"], defaultValues=["a", "b"], editable=True, multiValue=True
	)

	# Create config1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_insertObject", "params": [config1.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_getObjects", "params": [None, {"id": [config1.id]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert len(res["result"]) == 1
	config = res["result"][0]
	del config["ident"]
	assert config == config1.to_hash()

	# Update config1
	update_config = config1.to_hash()
	update_config["editable"] = None
	update_config["multiValue"] = None
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_updateObject", "params": [update_config]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_getObjects", "params": [None, {"id": [config1.id]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	assert len(res["result"]) == 1
	config = res["result"][0]
	del config["ident"]
	assert config == config1.to_hash()

	# Test client permissions
	test_client.reset_cookies()
	test_client.auth = (client1.id, client1.opsiHostKey)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_updateObject", "params": [config1.to_hash()]}
	res = test_client.post("/rpc", json=rpc).json()
	assert res["error"]["data"]["class"] == "BackendPermissionDeniedError"
