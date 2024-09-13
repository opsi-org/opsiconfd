# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
webdav tests
"""

import uuid
from typing import Generator
from unittest.mock import patch

import pytest
from opsicommon.exceptions import BackendPermissionDeniedError

from opsiconfd.backend.rpc.depot import (
	TRANSFER_SLOT_CONFIGS,
	TRANSFER_SLOT_RETENTION_TIME,
	TransferSlot,
	TransferSlotType,
)
from opsiconfd.backend.rpc.main import UnprotectedBackend
from opsiconfd.config import Config
from opsiconfd.redis import decode_redis_result, redis_client
from tests.backend.rpc.test_obj_config_state import _create_clients_and_depot

from ..utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	backend,
	config,
	sync_clean_redis,
	test_client,
)

TEST_SLOT_ID = "17676023-8426-4094-8ac7-ef4c22ac9803"


@pytest.fixture(autouse=True)
def clean_configs_and_objects(backend: UnprotectedBackend) -> Generator:  # noqa: F811
	sync_clean_redis()

	backend.configState_delete(configId=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], objectId="*")
	backend.config_delete(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC])

	yield

	sync_clean_redis()
	backend.configState_delete(configId=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], objectId="*")
	backend.config_delete(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC])


def _get_slots(test_client: OpsiconfdTestClient, number: int) -> list[dict]:  # noqa: F811
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
		assert result["result"].get("host_id") == "client1.uib.test"
		assert result["result"].get("retry_after") is None
		assert result["result"].get("retention") == TRANSFER_SLOT_RETENTION_TIME

		del result["result"]["retention"]
		slots.append(result["result"])

	return slots


# Acquiring a transfer slot when there are available slots.
def test_acquire_transfer_slot_available_slots(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	rpc = {"id": 1, "method": "depot_acquireTransferSlot", "params": ["depot1.uib.test", "client1.uib.test"]}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()

	# Assert the result
	assert result["result"].get("slot_id") is not None
	assert result["result"].get("depot_id") == "depot1.uib.test"
	assert result["result"].get("host_id") == "client1.uib.test"
	assert result["result"].get("retry_after") is None
	assert result["result"].get("retention") == TRANSFER_SLOT_RETENTION_TIME


def test_acquire_transfer_slot_with_slot_id(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	for i in range(12):
		rpc = {"id": 1, "method": "depot_acquireTransferSlot", "params": ["depot1.uib.test", "client1.uib.test", TEST_SLOT_ID]}
		res = test_client.post("/rpc", json=rpc)
		result = res.json()
		print(result)
		# Assert the result
		assert result["result"].get("slot_id") == TEST_SLOT_ID
		assert result["result"].get("depot_id") == "depot1.uib.test"
		assert result["result"].get("host_id") == "client1.uib.test"
		assert result["result"].get("retry_after") is None
		assert result["result"].get("retention") == TRANSFER_SLOT_RETENTION_TIME


def test_acquire_transfer_slot_max_default(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with patch("opsiconfd.backend.rpc.depot.TRANSFER_SLOT_MAX", 20):
		from opsiconfd.backend.rpc.depot import TRANSFER_SLOT_MAX

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
		assert result["result"].get("host_id") is None
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
		assert result["result"].get("host_id") is None
		assert result["result"].get("retry_after") is not None


def test_acquire_transfer_slot_max_config(
	test_client: OpsiconfdTestClient,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	clients, depot = _create_clients_and_depot(test_client)

	backend.config_create(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], defaultValues=[5])
	backend.configState_create(configId=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], objectId=depot["id"], values=[5])

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
		assert result["result"].get("host_id") == clients[1]["id"]
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
	assert result["result"].get("host_id") is None
	assert result["result"].get("retry_after") is not None


def test_acquire_transfer_slot_max_config_error(
	test_client: OpsiconfdTestClient,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with patch("opsiconfd.backend.rpc.depot.TRANSFER_SLOT_MAX", 20):
		from opsiconfd.backend.rpc.depot import TRANSFER_SLOT_MAX

		clients, depot = _create_clients_and_depot(test_client)

		config_name = TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC]
		backend.config_create(id=config_name, defaultValues=[4])
		backend.configState_create(configId=config_name, objectId=depot["id"], values=["invalid max"])

		# should use default max
		for i in range(TRANSFER_SLOT_MAX):
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
			assert result["result"].get("host_id") == clients[1]["id"]
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
		assert result["result"].get("host_id") is None
		assert result["result"].get("retry_after") is not None


def test_create_transfer_slot_with_depot_id() -> None:
	depot_id = "depot1.uib.test"
	host_id = "client1.uib.test"
	transfer_slot = TransferSlot(depot_id, host_id)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.host_id == host_id
	assert transfer_slot.slot_id is not None
	assert transfer_slot.retry_after is None


def test_create_transfer_slot_with_depot_id_and_slot_id() -> None:
	depot_id = "depot1.uib.test"
	host_id = "client1.uib.test"
	slot_id = TEST_SLOT_ID
	transfer_slot = TransferSlot(depot_id, host_id, slot_id)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.host_id == host_id
	assert str(transfer_slot.slot_id) == slot_id
	assert transfer_slot.retry_after is None


def test_create_transfer_slot_with_depot_id_slot_id_and_retry_after() -> None:
	depot_id = "depot1.uib.test"
	host_id = "client1.uib.test"
	slot_id = TEST_SLOT_ID
	retry_after = 60
	transfer_slot = TransferSlot(depot_id, host_id, slot_id, retry_after=retry_after)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.host_id == host_id
	assert transfer_slot.slot_id == uuid.UUID("urn:uuid:" + TEST_SLOT_ID)
	assert transfer_slot.retry_after is None


def test_transfer_slot_session_error(backend: UnprotectedBackend) -> None:  # noqa: F811
	with pytest.raises(BackendPermissionDeniedError) as excinfo:
		backend.depot_acquireTransferSlot(depot="depot1.uib.test", host="client1.uib.test")
		assert "Access denied" in str(excinfo.value)
	with pytest.raises(BackendPermissionDeniedError) as excinfo:
		backend.depot_releaseTransferSlot(depot="depot1.uib.test", host="client1.uib.test", slot_id=TEST_SLOT_ID)
		assert "Access denied" in str(excinfo.value)


def test_release_transfer_slot_with_slot_id(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	rpc = {"id": 1, "method": "depot_acquireTransferSlot", "params": ["depot1.uib.test", "client1.uib.test", TEST_SLOT_ID]}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()
	print(result)
	# Assert the result
	assert result["result"].get("slot_id") == TEST_SLOT_ID
	assert result["result"].get("depot_id") == "depot1.uib.test"
	assert result["result"].get("host_id") == "client1.uib.test"
	assert result["result"].get("retry_after") is None

	redis = redis_client()
	redis_res = decode_redis_result(redis.keys())
	print(redis_res)
	redis_res = decode_redis_result(
		redis.get(f"{config.redis_key('slot')}:depot1.uib.test:{TransferSlotType.OPSICLIENTD_PRODUCT_SYNC}:client1.uib.test:{TEST_SLOT_ID}")
	)
	print(redis_res)
	assert redis_res == "client1.uib.test"
	redis_res = decode_redis_result(
		redis.ttl(f"{config.redis_key('slot')}:depot1.uib.test:{TransferSlotType.OPSICLIENTD_PRODUCT_SYNC}:client1.uib.test:{TEST_SLOT_ID}")
	)
	assert 10 < redis_res <= 60

	rpc = {"id": 1, "method": "depot_releaseTransferSlot", "params": ["depot1.uib.test", "client1.uib.test", TEST_SLOT_ID]}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()

	assert result["error"] is None

	redis_res = decode_redis_result(redis.get(f"{config.redis_key('slot')}:depot1.uib.test:client1.uib.test:{TEST_SLOT_ID}"))
	print(redis_res)
	assert redis_res is None


def test_return_list_with_valid_input(
	test_client: OpsiconfdTestClient,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	backend.config_create(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], defaultValues=[40])

	excepted_slots = _get_slots(test_client, 40)

	rpc = {
		"id": 1,
		"method": "depot_listTransferSlot",
		"params": ["depot1.uib.test"],
	}
	res = test_client.post("/rpc", json=rpc)
	result = res.json()
	slots = result["result"]

	assert len(slots) == 40
	for slot in slots:
		for expected_slot in excepted_slots:
			if expected_slot["slot_id"] == slot["slot_id"]:
				for key, value in expected_slot.items():
					assert slot[key] == value
				excepted_slots.remove(expected_slot)
				break


def test_valid_redis_key_with_all_values() -> None:
	key = f"slot:depot1.uib.test:{TransferSlotType.OPSICLIENTD_PRODUCT_SYNC}:client1.uib.test:{TEST_SLOT_ID}"
	transfer_slot = TransferSlot.from_redis_key(key)
	assert transfer_slot
	assert transfer_slot.depot_id == "depot1.uib.test"
	assert transfer_slot.host_id == "client1.uib.test"
	assert isinstance(transfer_slot.slot_id, uuid.UUID)
	assert transfer_slot.slot_id == uuid.UUID("urn:uuid:" + TEST_SLOT_ID)


def test_invalid_redis_key() -> None:
	key = "invalidrediskey:test"
	transfer_slot = TransferSlot.from_redis_key(key)
	assert transfer_slot is None


def test_type_distinction(config: Config, test_client: OpsiconfdTestClient) -> None:  # noqa: F811  # noqa: F811
	depot_id = "depot1.uib.test"
	host_id = "client1.uib.test"
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	for slot_type in TransferSlotType:
		rpc = {
			"id": 1,
			"method": "depot_acquireTransferSlot",
			"params": [depot_id, host_id, None, slot_type],
		}
		result = test_client.post("/rpc", json=rpc)
		print(result)
	redis = redis_client()
	assert len(list(redis.scan_iter(f"{config.redis_key('slot')}:{depot_id}:*"))) == len(TransferSlotType)
	for slot_type in TransferSlotType:
		assert len(list(redis.scan_iter(f"{config.redis_key('slot')}:{depot_id}:{slot_type}:*"))) == 1


def test_acquire_transfer_slot_max_per_type(
	test_client: OpsiconfdTestClient,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with patch("opsiconfd.backend.rpc.depot.TRANSFER_SLOT_MAX", 3):
		from opsiconfd.backend.rpc.depot import TRANSFER_SLOT_MAX

		clients, depot = _create_clients_and_depot(test_client)
		test_client.auth = (ADMIN_USER, ADMIN_PASS)

		for slot_type in TransferSlotType:
			backend.config_create(id=TRANSFER_SLOT_CONFIGS[slot_type], defaultValues=[1])
			for i in range(TRANSFER_SLOT_MAX):
				rpc = {
					"id": 1,
					"method": "depot_acquireTransferSlot",
					"params": [depot["id"], clients[1]["id"], None, slot_type],
				}
				res = test_client.post("/rpc", json=rpc)
				result = res.json()
				print(result)
				if i == 0:
					assert result["result"].get("slot_id") is not None
					assert result["result"].get("depot_id") == depot["id"]
					assert result["result"].get("host_id") == clients[1]["id"]
					assert result["result"].get("retry_after") is None
				else:
					assert result["result"].get("slot_id") is None
					assert result["result"].get("depot_id") is None
					assert result["result"].get("host_id") is None
					assert result["result"].get("retry_after") is not None
