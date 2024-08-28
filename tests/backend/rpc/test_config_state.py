# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd.backend.rpc.obj_config_state
"""

from pathlib import Path
from typing import Any, Generator

import pytest
from opsicommon.objects import ConfigState, OpsiClient, OpsiDepotserver, UnicodeConfig

from opsiconfd.backend.rpc.main import ProtectedBackend, UnprotectedBackend
from opsiconfd.config import get_configserver_id
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	backend,
	clean_mysql,
	clean_redis,
	get_config,
	test_client,
)


@pytest.fixture()
def acl_file(tmp_path: Path) -> Generator[Path, None, None]:
	_acl_file = tmp_path / "acl.conf"
	data = (
		f"config_getObjects       : sys_user({ADMIN_USER}); opsi_depotserver; opsi_client\n"
		f"configState_getObjects  : sys_user({ADMIN_USER}); self; opsi_depotserver\n"
		f".*                      : sys_user({ADMIN_USER}); opsi_client; opsi_depotserver\n"
	)
	_acl_file.write_text(data=data, encoding="utf-8")
	protected_backend = ProtectedBackend()
	try:
		with get_config({"acl_file": str(_acl_file)}):
			protected_backend._read_acl_file()
		yield _acl_file
	finally:
		# Restore original ACL
		protected_backend._read_acl_file()


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
		"id": "test-backend-rpc-depot.opsi.test",
		"opsiHostKey": "7dec5913c501a28545860d576768924f",
		"description": "description",
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


def _create_test_server_config(test_client: OpsiconfdTestClient, config_id: str) -> dict[str, Any]:  # noqa: F811
	# create config on configserver
	server_conf = {
		"id": config_id,
		"description": "bootimage append",
		"possibleValues": ["vga=normal", "acpi=off", "reboot=b"],
		"defaultValues": ["vga=normal"],
		"editable": True,
		"multiValue": True,
	}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_create", "params": server_conf}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return server_conf


def _set_config_state(
	test_client: OpsiconfdTestClient,  # noqa: F811
	object_id: str,
	config_id: str,
	values: list,
) -> dict[str, Any]:
	# Set config state on depot, client 2 should use this config value
	conf = {"configId": config_id, "objectId": object_id, "values": values}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_create", "params": conf}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	return conf


def test_config_state_get_values(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	clients, depot = _create_clients_and_depot(test_client)

	# create config on configserver
	default_conf = _create_test_server_config(test_client, "test-backend-rpc-obj-config")

	# both clients should use server default
	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	for client in clients:
		assert res["result"][client["id"]]["test-backend-rpc-obj-config"] == default_conf["defaultValues"]

	# set config state on server, client 1 should use this value, client 2 should still use the default value
	server_conf = _set_config_state(test_client, get_configserver_id(), "test-backend-rpc-obj-config", ["acpi=on"])

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getObjects", "params": []}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)

	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][clients[0]["id"]]["test-backend-rpc-obj-config"] == server_conf["values"]
	assert res["result"][clients[1]["id"]]["test-backend-rpc-obj-config"] == default_conf["defaultValues"]

	# Set config state on depot, client 2 should use this config value
	depot_conf = _set_config_state(test_client, depot["id"], "test-backend-rpc-obj-config", ["acpi=off"])
	default_conf2 = _create_test_server_config(test_client, "test-backend-rpc-obj-config2")

	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][clients[0]["id"]]["test-backend-rpc-obj-config"] == server_conf["values"]
	assert res["result"][clients[1]["id"]]["test-backend-rpc-obj-config"] == depot_conf["values"]

	params = {"config_ids": [], "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][clients[0]["id"]]["test-backend-rpc-obj-config"] == server_conf["values"]
	assert res["result"][clients[1]["id"]]["test-backend-rpc-obj-config"] == depot_conf["values"]
	assert res["result"][clients[0]["id"]]["test-backend-rpc-obj-config2"] == default_conf2["defaultValues"]
	assert res["result"][clients[1]["id"]]["test-backend-rpc-obj-config2"] == default_conf2["defaultValues"]

	# Set config values for clients, clients should use this value
	client_conf1 = {"configId": "test-backend-rpc-obj-config", "objectId": clients[0]["id"], "values": ["reboot=b"]}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_create", "params": client_conf1}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res

	client_conf2 = {"configId": "test-backend-rpc-obj-config", "objectId": clients[1]["id"], "values": ["reboot=b"]}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_create", "params": client_conf2}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res

	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][clients[0]["id"]]["test-backend-rpc-obj-config"] == client_conf2["values"]
	assert res["result"][clients[1]["id"]]["test-backend-rpc-obj-config"] == client_conf2["values"]

	# delete all config states client should use server default again
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "configState_deleteObjects",
		"params": [[depot_conf, client_conf1, client_conf2, server_conf]],
	}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res

	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	for client in clients:
		assert res["result"][client["id"]]["test-backend-rpc-obj-config"] == default_conf["defaultValues"]


def test_cs_get_values_rename_depot(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	clients, depot = _create_clients_and_depot(test_client)

	_create_test_server_config(test_client, "test-backend-rpc-obj-config")

	# Set config state on depot, client 2 should use this config value
	depot_conf = _set_config_state(test_client, depot["id"], "test-backend-rpc-obj-config", ["acpi=off"])

	# renmame depot, new config state should exist, client 2 should use value from depot
	new_depot_id = "new-depot-id.opsi.test"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_renameOpsiDepotserver", "params": [depot["id"], new_depot_id]}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "configState_getObjects",
		"params": [[], {"objectId": new_depot_id, "configId": depot_conf["configId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][0]["configId"] == depot_conf["configId"]
	assert res["result"][0]["values"] == depot_conf["values"]

	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][clients[0]["id"]]["test-backend-rpc-obj-config"] == ["vga=normal"]
	assert res["result"][clients[1]["id"]]["test-backend-rpc-obj-config"] == ["acpi=off"]


def test_configState_getClientToDepotserver(backend: UnprotectedBackend) -> None:  # noqa: F811
	depot1 = OpsiDepotserver(id="test-config-state-depot-1.opsi.test")
	client1 = OpsiClient(id="test-config-state-client-1.opsi.test")
	client2 = OpsiClient(id="test-config-state-client-2.opsi.test")

	server_id = backend.host_getIdents(type="OpsiConfigserver")[0]

	backend.host_createObjects([depot1, client1, client2])

	for depot_ids in server_id, [server_id], [], None:
		client_to_depots = backend.configState_getClientToDepotserver(depotIds=depot_ids)
		assert len(client_to_depots) == 2
		for client_to_depot in client_to_depots:
			assert client_to_depot["depotId"] == server_id
			assert client_to_depot["clientId"] in (client1.id, client2.id)

	client_to_depots = backend.configState_getClientToDepotserver(clientIds=client1.id)
	assert len(client_to_depots) == 1
	assert client_to_depots[0]["depotId"] == server_id
	assert client_to_depots[0]["clientId"] == client1.id

	client_to_depots = backend.configState_getClientToDepotserver(depotIds=server_id, clientIds=[client1.id])
	assert len(client_to_depots) == 1
	assert client_to_depots[0]["depotId"] == server_id
	assert client_to_depots[0]["clientId"] == client1.id

	client_to_depots = backend.configState_getClientToDepotserver(depotIds=depot1.id)
	assert len(client_to_depots) == 0

	config_state = ConfigState(configId="clientconfig.depot.id", objectId=client1.id, values=[depot1.id])
	backend.configState_createObjects([config_state])

	client_to_depots = backend.configState_getClientToDepotserver(depotIds=depot1.id)
	assert len(client_to_depots) == 1
	assert client_to_depots[0]["depotId"] == depot1.id
	assert client_to_depots[0]["clientId"] == client1.id

	client_to_depots = backend.configState_getClientToDepotserver(depotIds=server_id, clientIds=[client1.id])
	assert len(client_to_depots) == 0

	client_to_depots = backend.configState_getClientToDepotserver(depotIds=server_id, clientIds=[])
	assert len(client_to_depots) == 1
	assert client_to_depots[0]["depotId"] == server_id
	assert client_to_depots[0]["clientId"] == client2.id


def test_configState_getObjects(
	acl_file: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client1 = OpsiClient(id="test-backend-rpc-obj-config-state-1.opsi.test", opsiHostKey="c68857de49124e5860d3c501a2675795")
	client2 = OpsiClient(id="test-backend-rpc-obj-config-state-2.opsi.test", opsiHostKey="63c5d9127de4a24086510e5c79688575")
	config1 = UnicodeConfig(
		id="test-backend-rpc-obj-config-state-1",
		description="test desc",
		possibleValues=["a", "b", "c"],
		defaultValues=["a", "b"],
		editable=True,
		multiValue=True,
	)
	config_state1 = ConfigState(configId=config1.id, objectId=client1.id, values=["a", "b"])
	config_state2 = ConfigState(configId=config1.id, objectId=client2.id, values=["b", "c"])

	res = test_client.jsonrpc20(method="host_createObjects", params=[[client1, client2]])
	assert "error" not in res
	res = test_client.jsonrpc20(method="config_createObjects", params=[[config1]])
	assert "error" not in res
	res = test_client.jsonrpc20(method="configState_createObjects", params=[[config_state1, config_state2]])
	assert "error" not in res

	for filter in ({}, {"configId": config1.id}, {"objectId": [client1.id, client2.id]}):
		res = test_client.jsonrpc20(method="configState_getObjects", params=[[], filter])
		assert "error" not in res
		assert len(res["result"]) == 2

	# Test client permissions
	test_client.reset_cookies()
	assert client1.opsiHostKey
	test_client.auth = (client1.id, client1.opsiHostKey)

	for filter in ({}, {"configId": config1.id}, {"objectId": [client1.id, client2.id]}):
		res = test_client.jsonrpc20(method="configState_getObjects", params=[[], filter])
		print(res)
		assert "error" not in res
		assert len(res["result"]) == 1
		assert res["result"][0].configId == config1.id
		assert res["result"][0].objectId == client1.id
