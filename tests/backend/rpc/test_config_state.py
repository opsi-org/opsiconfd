# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_config_state
"""

from typing import Any, Generator

import pytest
from opsiconfd.backend.mysql.cleanup import remove_orphans_config_state
from opsiconfd.backend.mysql import MySQLConnection

from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Connection,
	OpsiconfdTestClient,
	database_connection,
	test_client,
	clean_redis,
	backend,
)


@pytest.fixture(autouse=False)
def cleanup_database(database_connection: Connection) -> Generator[None, None, None]:  # pylint: disable=redefined-outer-name
	cursor = database_connection.cursor()
	cursor.execute("DELETE FROM `CONFIG_VALUE` WHERE configId LIKE 'test-backend-rpc-obj-config%'")
	cursor.execute("DELETE FROM `CONFIG_STATE` WHERE objectId LIKE 'test-backend-rpc%'")
	cursor.execute("DELETE FROM `CONFIG` WHERE configId LIKE 'test-backend-rpc-obj-config%'")
	cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test-backend-rpc-%'")
	database_connection.commit()
	yield
	cursor.execute("DELETE FROM `CONFIG_VALUE` WHERE configId LIKE 'test-backend-rpc-obj-config%'")
	cursor.execute("DELETE FROM `CONFIG_STATE` WHERE objectId LIKE 'test-backend-rpc%'")
	cursor.execute("DELETE FROM `CONFIG` WHERE configId LIKE 'test-backend-rpc-obj-config%'")
	cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test-backend-rpc-%'")
	database_connection.commit()
	cursor.close()


def _create_clients_and_depot(
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name
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


def _create_test_server_config(test_client: OpsiconfdTestClient) -> dict[str, Any]:  # pylint: disable=redefined-outer-name
	# create config on configserver
	server_conf = {
		"id": "test-backend-rpc-obj-config",
		"description": "bootimage append",
		"possibleValues": ["vga=normal", "acpi=off", "reboot=b"],
		"defaultValues": ["vga=normal"],
		"editable": True,
		"multiValue": True,
	}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "config_create", "params": server_conf}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	return server_conf


def _set_config_state(
	test_client: OpsiconfdTestClient, object_id: str, config_id: str, values: list  # pylint: disable=redefined-outer-name
) -> dict[str, Any]:

	# Set config state on depot, client 2 should use this config value
	conf = {"configId": config_id, "objectId": object_id, "values": values}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_create", "params": conf}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	return conf


def test_config_state_get_values(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name, too-many-statements

	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	clients, depot = _create_clients_and_depot(test_client)

	# create config on configserver
	_create_test_server_config(test_client)

	# both clients should use server default
	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	for client in clients:
		assert res["result"][client["id"]]["test-backend-rpc-obj-config"] == ["vga=normal"]

	# Set config state on depot, client 2 should use this config value
	depot_conf = _set_config_state(test_client, depot["id"], "test-backend-rpc-obj-config", ["acpi=off"])

	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][clients[0]["id"]]["test-backend-rpc-obj-config"] == ["vga=normal"]
	assert res["result"][clients[1]["id"]]["test-backend-rpc-obj-config"] == ["acpi=off"]

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
	assert res["result"][clients[0]["id"]]["test-backend-rpc-obj-config"] == ["reboot=b"]
	assert res["result"][clients[1]["id"]]["test-backend-rpc-obj-config"] == ["reboot=b"]

	# delete all config states client should use server default again
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_deleteObjects", "params": [[depot_conf, client_conf1, client_conf2]]}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res

	params = {"config_ids": "test-backend-rpc-obj-config", "object_ids": [clients[0]["id"], clients[1]["id"]], "with_defaults": True}
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "configState_getValues", "params": params}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	for client in clients:
		assert res["result"][client["id"]]["test-backend-rpc-obj-config"] == ["vga=normal"]


def test_cs_get_values_rename_depot(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name, too-many-statements

	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	clients, depot = _create_clients_and_depot(test_client)

	_create_test_server_config(test_client)
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


def test_config_state_cleanup(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name

	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	clients, depot = _create_clients_and_depot(test_client)

	print(clients)
	print(depot)

	_create_test_server_config(test_client)
	# Set config state on depot, client 2 should use this config value
	depot_conf = _set_config_state(test_client, depot["id"], "test-backend-rpc-obj-config", ["acpi=off"])

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

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "configState_getObjects",
		"params": [[], {"objectId": depot["id"], "configId": depot_conf["configId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"][0]["configId"] == depot_conf["configId"]
	assert res["result"][0]["values"] == depot_conf["values"]

	mysql = MySQLConnection()
	with mysql.connection():
		with mysql.session() as session:
			remove_orphans_config_state(session)

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "configState_getObjects",
		"params": [[], {"objectId": depot["id"], "configId": depot_conf["configId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	print(res)
	assert "error" not in res
	assert res["result"] == []
