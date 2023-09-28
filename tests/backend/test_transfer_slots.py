# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav tests
"""
from typing import Generator
from mock import patch

import pytest
from opsicommon.exceptions import BackendPermissionDeniedError
from opsiconfd.backend import get_unprotected_backend

from opsiconfd.backend.rpc.depot import (
	TRANSFER_SLOT_CONFIG,
	TRANSFER_SLOT_MAX,
	TRANSFER_SLOT_RETENTION_TIME,
	TransferSlot,
	RPCDepotserverMixin,
)
from opsiconfd.backend.rpc.main import UnprotectedBackend
from opsiconfd.config import Config
from opsiconfd.redis import decode_redis_result
from tests.backend.rpc.test_config_state import _create_clients_and_depot

from ..utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	backend,
	config,
	sync_clean_redis,
	sync_redis_client,
	test_client,
)

TEST_SLOT_ID = "17676023-8426-4094-8ac7-ef4c22ac9803"


@pytest.fixture(autouse=True)
def clean_configs_and_objects(backend: UnprotectedBackend) -> Generator:  # pylint: disable=redefined-outer-name
	sync_clean_redis()

	backend.configState_delete(configId=TRANSFER_SLOT_CONFIG, objectId="*")
	backend.config_delete(id=TRANSFER_SLOT_CONFIG)

	yield

	sync_clean_redis()
	backend.configState_delete(configId=TRANSFER_SLOT_CONFIG, objectId="*")
	backend.config_delete(id=TRANSFER_SLOT_CONFIG)


def _get_slots(test_client: OpsiconfdTestClient, number: int) -> list[dict]:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	slots = []
	for i in range(number):
		print(i)
		# Call the method under test
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		rpc = {
			"id": 1,
			"method": "depot_acquireTransferSlot",
			"params": ["depot1.uib.test", "client1.uib.test"],
		}
		res = test_client.post("/rpc", json=rpc)
		result = res.json()
		print(result)
		# Assert the result
		assert result["result"].get("slot_id") is not None
		assert result["result"].get("depot_id") == "depot1.uib.test"
		assert result["result"].get("client_id") == "client1.uib.test"
		assert result["result"].get("retry_after") is None
		assert result["result"].get("retention") == TRANSFER_SLOT_RETENTION_TIME

		del result["result"]["retention"]
		slots.append(result["result"])

	return slots


# Acquiring a transfer slot when there are available slots.
def test_acquire_transfer_slot_available_slots(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	rpc = {"id": 1, "method": "depot_acquireTransferSlot", "params": ["depot1.uib.test", "client1.uib.test"]}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()

	# Assert the result
	assert result["result"].get("slot_id") is not None
	assert result["result"].get("depot_id") == "depot1.uib.test"
	assert result["result"].get("client_id") == "client1.uib.test"
	assert result["result"].get("retry_after") is None
	assert result["result"].get("retention") == TRANSFER_SLOT_RETENTION_TIME


def test_acquire_transfer_slot_with_slot_id(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	for i in range(12):  # pylint: disable=unused-variable
		rpc = {"id": 1, "method": "depot_acquireTransferSlot", "params": ["depot1.uib.test", "client1.uib.test", TEST_SLOT_ID]}
		res = test_client.post("/rpc", json=rpc)
		result = res.json()
		print(result)
		# Assert the result
		assert result["result"].get("slot_id") == TEST_SLOT_ID
		assert result["result"].get("depot_id") == "depot1.uib.test"
		assert result["result"].get("client_id") == "client1.uib.test"
		assert result["result"].get("retry_after") is None
		assert result["result"].get("retention") == TRANSFER_SLOT_RETENTION_TIME


def test_acquire_transfer_slot_max(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	_get_slots(test_client, TRANSFER_SLOT_MAX)

	rpc = {
		"id": 1,
		"method": "depot_acquireTransferSlot",
		"params": ["depot1.uib.test", "client1.uib.test"],
	}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()
	print(result)
	# Assert the result
	assert result["result"].get("slot_id") is None
	assert result["result"].get("depot_id") is None
	assert result["result"].get("client_id") is None
	assert result["result"].get("retry_after") is not None

	rpc = {
		"id": 1,
		"method": "depot_acquireTransferSlot",
		"params": ["depot1.uib.test", "client1.uib.test", TEST_SLOT_ID],
	}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()
	print(result)
	# Assert the result
	assert result["result"].get("slot_id") is None
	assert result["result"].get("depot_id") is None
	assert result["result"].get("client_id") is None
	assert result["result"].get("retry_after") is not None


def test_acquire_transfer_slot_max_config(  # pylint: disable=redefined-outer-name
	test_client: OpsiconfdTestClient, backend: UnprotectedBackend
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	clients, depot = _create_clients_and_depot(test_client)

	backend.config_create(id=TRANSFER_SLOT_CONFIG, defaultValues=[5])
	backend.configState_create(configId=TRANSFER_SLOT_CONFIG, objectId=depot["id"], values=[5])

	for i in range(5):
		print(i)
		# Call the method under test
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		rpc = {
			"id": 1,
			"method": "depot_acquireTransferSlot",
			"params": [depot["id"], clients[1]["id"]],
		}
		res = test_client.post("/rpc", json=rpc)
		result = res.json()
		print(result)
		# Assert the result
		assert result["result"].get("slot_id") is not None
		assert result["result"].get("depot_id") == depot["id"]
		assert result["result"].get("client_id") == clients[1]["id"]
		assert result["result"].get("retry_after") is None

	rpc = {
		"id": 1,
		"method": "depot_acquireTransferSlot",
		"params": [depot["id"], clients[1]["id"]],
	}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()
	print(result)
	# Assert the result
	assert result["result"].get("slot_id") is None
	assert result["result"].get("depot_id") is None
	assert result["result"].get("client_id") is None
	assert result["result"].get("retry_after") is not None


def test_create_transfer_slot_with_depot_id() -> None:
	depot_id = "depot1.uib.test"
	client_id = "client1.uib.test"
	transfer_slot = TransferSlot(depot_id, client_id)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.client_id == client_id
	assert transfer_slot.slot_id is not None
	assert transfer_slot.retry_after is None


def test_create_transfer_slot_with_depot_id_and_slot_id() -> None:
	depot_id = "depot1.uib.test"
	client_id = "client1.uib.test"
	slot_id = TEST_SLOT_ID
	transfer_slot = TransferSlot(depot_id, client_id, slot_id)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.client_id == client_id
	assert str(transfer_slot.slot_id) == slot_id
	assert transfer_slot.retry_after is None


def test_create_transfer_slot_with_depot_id_slot_id_and_retry_after() -> None:
	depot_id = "depot1.uib.test"
	client_id = "client1.uib.test"
	slot_id = TEST_SLOT_ID
	retry_after = 60
	transfer_slot = TransferSlot(depot_id, client_id, slot_id, retry_after)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.client_id == client_id
	assert transfer_slot.slot_id is None
	assert transfer_slot.retry_after == retry_after


def test_transfer_slot_session_error(backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	with pytest.raises(BackendPermissionDeniedError) as excinfo:
		backend.depot_acquireTransferSlot(depot="depot1.uib.test", client="client1.uib.test")
		assert "Access denied" in str(excinfo.value)
	with pytest.raises(BackendPermissionDeniedError) as excinfo:
		backend.depot_releaseTransferSlot(depot="depot1.uib.test", client="client1.uib.test", slot_id=TEST_SLOT_ID)
		assert "Access denied" in str(excinfo.value)


def test_release_transfer_slot_with_slot_id(  # pylint: disable=redefined-outer-name
	test_client: OpsiconfdTestClient, config: Config
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	rpc = {"id": 1, "method": "depot_acquireTransferSlot", "params": ["depot1.uib.test", "client1.uib.test", TEST_SLOT_ID]}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()
	print(result)
	# Assert the result
	assert result["result"].get("slot_id") == TEST_SLOT_ID
	assert result["result"].get("depot_id") == "depot1.uib.test"
	assert result["result"].get("client_id") == "client1.uib.test"
	assert result["result"].get("retry_after") is None

	with sync_redis_client() as redis_client:
		redis_res = decode_redis_result(redis_client.keys())
		print(redis_res)
		redis_res = decode_redis_result(redis_client.get(f"{config.redis_key('slot')}:depot1.uib.test:client1.uib.test:{TEST_SLOT_ID}"))
		print(redis_res)
		assert redis_res == "client1.uib.test"
		redis_res = decode_redis_result(redis_client.ttl(f"{config.redis_key('slot')}:depot1.uib.test:client1.uib.test:{TEST_SLOT_ID}"))
		assert 10 < redis_res <= 60

	rpc = {"id": 1, "method": "depot_releaseTransferSlot", "params": ["depot1.uib.test", "client1.uib.test", TEST_SLOT_ID]}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()

	assert result["error"] is None

	with sync_redis_client() as redis_client:
		redis_res = decode_redis_result(redis_client.get(f"{config.redis_key('slot')}:depot1.uib.test:client1.uib.test:{TEST_SLOT_ID}"))
		print(redis_res)
		assert redis_res is None


def test_return_list_with_valid_input(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	excepted_slots = _get_slots(test_client, TRANSFER_SLOT_MAX)

	rpc = {
		"id": 1,
		"method": "depot_listTransferSlot",
		"params": ["depot1.uib.test"],
	}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()
	slots = result["result"]

	assert len(slots) == TRANSFER_SLOT_MAX
	for slot in slots:
		for expected_slot in excepted_slots:
			if expected_slot["slot_id"] == slot["slot_id"]:
				for key, value in expected_slot.items():
					assert slot[key] == value
				excepted_slots.remove(expected_slot)  # pylint: disable=modified-iterating-list
				break
