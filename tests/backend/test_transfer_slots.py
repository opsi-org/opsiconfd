# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

import uuid
from collections.abc import Generator
from typing import Literal

import pytest
from opsi.exception import BackendPermissionDeniedError
from opsi.opsi.service.model.object import OpsiClient, OpsiDepotserver, generate_opsi_host_key

from opsiconfd.backend.rpc.depot import TRANSFER_SLOT_CONFIGS, TRANSFER_SLOT_RETENTION_TIME, TransferSlot, TransferSlotType
from opsiconfd.backend.rpc.main import UnprotectedBackend
from opsiconfd.config import Config
from opsiconfd.redis import decode_redis_result, redis_client

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


@pytest.fixture
def prepare_and_cleanup(backend: UnprotectedBackend) -> Generator[tuple[list[OpsiDepotserver], list[OpsiClient]]]:  # noqa: F811
	"""
	Creates two depots and ten clients for testing transfer slots.
	Returns a tuple containing the list of created clients and depots.
	Cleans up the created clients and depots after the test.

	"""
	sync_clean_redis()

	backend.configState_delete(configId=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], objectId="*")
	backend.config_delete(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC])
	clients = [OpsiClient(id=f"client-transfer-slot-test-{i}.uib.test", opsiHostKey=generate_opsi_host_key()) for i in range(10)]
	depots = [
		OpsiDepotserver(id="depot-transfer-slot-test-1.uib.test", opsiHostKey=generate_opsi_host_key()),
		OpsiDepotserver(id="depot-transfer-slot-test-2.uib.test", opsiHostKey=generate_opsi_host_key()),
	]
	backend.host_createObjects(depots + clients)

	yield depots, clients

	backend.host_deleteObjects(depots + clients)
	backend.configState_delete(configId=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], objectId="*")
	backend.config_delete(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC])

	sync_clean_redis()


def test_valid_redis_key_with_all_values() -> None:
	key = f"slot:depot1.uib.test:{TransferSlotType.OPSICLIENTD_PRODUCT_SYNC}:client1.uib.test:{TEST_SLOT_ID}"
	transfer_slot = TransferSlot.from_redis_key(key)
	assert transfer_slot
	assert transfer_slot.depot_id == "depot1.uib.test"
	assert transfer_slot.host_id == "client1.uib.test"
	assert isinstance(transfer_slot.slot_id, uuid.UUID)
	assert transfer_slot.slot_id == uuid.UUID(TEST_SLOT_ID)


def test_invalid_redis_key() -> None:
	key = "invalidrediskey:test"
	transfer_slot = TransferSlot.from_redis_key(key)
	assert transfer_slot is None


@pytest.mark.parametrize("retry_after", [None, 60])
@pytest.mark.parametrize("slot_id", [None, TEST_SLOT_ID])
def test_create_transfer_slot(retry_after: int | None, slot_id: str | None) -> None:
	depot_id = "depot1.uib.test"
	host_id = "client1.uib.test"
	transfer_slot = TransferSlot(depot_id, host_id, slot_id, retry_after=retry_after)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.host_id == host_id
	if slot_id:
		assert str(transfer_slot.slot_id) == slot_id
		# If a slot_id is present, retry_after must be None
		assert transfer_slot.retry_after is None
	else:
		# If no slot_id is present, retry_after should be set as provided
		assert transfer_slot.retry_after == retry_after


@pytest.mark.parametrize("config_type", ["global", "depot"])
def test_acquire_transfer_slot_max(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	prepare_and_cleanup: tuple[list[OpsiDepotserver], list[OpsiClient]],
	config_type: Literal["global", "depot"],
) -> None:
	depots, clients = prepare_and_cleanup

	if config_type == "global":
		backend.config_create(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], defaultValues=[3])
	else:
		backend.config_create(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], defaultValues=[20])
		for depot in depots:
			backend.configState_create(
				configId=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], objectId=depot.id, values=[3]
			)

	redis = redis_client()
	keys = decode_redis_result(redis.keys(f"{config.redis_key('slot')}:*"))
	assert keys == []

	for depot_num in range(2):
		slots = []
		for client_num in range(4):
			client = clients[client_num]
			test_client.reset_cookies()
			test_client.auth = str(client.id), str(client.opsiHostKey)
			response = test_client.post(
				"/rpc",
				json={
					"id": 1,
					"method": "depot_acquireTransferSlot",
					"params": [depots[depot_num].id, client.id],
				},
			).json()

			keys = decode_redis_result(redis.keys(f"{config.redis_key('slot')}:{depots[depot_num].id}:opsiclientd_product_sync:*"))

			if client_num < 3:
				assert len(keys) == client_num + 1
				assert response["result"].get("slot_id") is not None
				assert response["result"].get("depot_id") == depots[depot_num].id
				assert response["result"].get("host_id") == client.id
				assert response["result"].get("retry_after") is None
				assert response["result"].get("retention") == TRANSFER_SLOT_RETENTION_TIME
				slots.append(response["result"])
			else:
				assert len(keys) == 3
				assert response["result"].get("slot_id") is None
				assert response["result"].get("depot_id") is None
				assert response["result"].get("host_id") is None
				assert TRANSFER_SLOT_RETENTION_TIME <= response["result"].get("retry_after") <= TRANSFER_SLOT_RETENTION_TIME * 2
				assert response["result"].get("retention") == TRANSFER_SLOT_RETENTION_TIME

			assert len(keys) == len(slots)

			# Test depot_listTransferSlot
			test_client.reset_cookies()
			test_client.auth = (ADMIN_USER, ADMIN_PASS)
			response = test_client.post(
				"/rpc",
				json={
					"id": 1,
					"method": "depot_listTransferSlot",
					"params": [depots[depot_num].id],
				},
			).json()
			res_slots = response["result"]
			assert len(res_slots) == len(slots)
			assert sorted(res_slots, key=lambda x: x.get("slot_id")) == sorted(slots, key=lambda x: x.get("slot_id"))


def test_acquire_transfer_slot_max_per_type(
	test_client: OpsiconfdTestClient,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	prepare_and_cleanup: tuple[list[OpsiDepotserver], list[OpsiClient]],
) -> None:
	depots, clients = prepare_and_cleanup

	depot = depots[0]
	client = clients[0]
	backend.config_create(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], defaultValues=[20])
	backend.config_create(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSI_PACKAGE_UPDATER], defaultValues=[20])
	backend.configState_create(configId=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], objectId=depot.id, values=[2])
	backend.configState_create(configId=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSI_PACKAGE_UPDATER], objectId=depot.id, values=[3])

	test_client.auth = (str(client.id), str(client.opsiHostKey))
	for slot_type in (TransferSlotType.OPSICLIENTD_PRODUCT_SYNC, TransferSlotType.OPSI_PACKAGE_UPDATER):
		max = 2 if slot_type == TransferSlotType.OPSICLIENTD_PRODUCT_SYNC else 3
		for slot_num in range(max):
			result = test_client.post(
				"/rpc",
				json={
					"id": 1,
					"method": "depot_acquireTransferSlot",
					"params": [depot.id, client.id, None, slot_type],
				},
			).json()
			if slot_num <= max:
				assert result["result"].get("slot_id") is not None
				assert result["result"].get("depot_id") == depot.id
				assert result["result"].get("host_id") == client.id
				assert result["result"].get("retry_after") is None
			else:
				assert result["result"].get("slot_id") is None
				assert result["result"].get("depot_id") is None
				assert result["result"].get("host_id") is None
				assert result["result"].get("retry_after") is not None


def test_acquire_transfer_slot_reacquire(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	prepare_and_cleanup: tuple[list[OpsiDepotserver], list[OpsiClient]],
) -> None:
	depots, clients = prepare_and_cleanup

	backend.config_create(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], defaultValues=[3])

	redis = redis_client()
	keys = decode_redis_result(redis.keys(f"{config.redis_key('slot')}:*"))
	assert keys == []

	client = clients[0]
	test_client.reset_cookies()
	test_client.auth = str(client.id), str(client.opsiHostKey)

	slot_ids = []
	for slot_num in range(5):
		response = test_client.post(
			"/rpc",
			json={
				"id": 1,
				"method": "depot_acquireTransferSlot",
				"params": [depots[0].id, client.id],
			},
		).json()

		slot_id = response["result"].get("slot_id")
		keys = decode_redis_result(redis.keys(f"{config.redis_key('slot')}:{depots[0].id}:opsiclientd_product_sync:{client.id}:*"))

		if slot_num < 3:
			# A client can acquire mutliple transfer slots until the limit is reached
			assert slot_id is not None
			assert len(keys) == slot_num + 1
			slot_ids.append(slot_id)
		else:
			assert slot_id is None
			assert len(keys) == 3

	old_keys = []
	for _ in range(5):
		response = test_client.post(
			"/rpc",
			json={
				"id": 1,
				"method": "depot_acquireTransferSlot",
				"params": [depots[0].id, client.id, slot_ids[1]],
			},
		).json()

		slot_id = response["result"].get("slot_id")
		keys = decode_redis_result(redis.keys(f"{config.redis_key('slot')}:{depots[0].id}:opsiclientd_product_sync:{client.id}:*"))
		keys.sort()

		# The client should be able to reacquire the same transfer slot successfully
		assert slot_id == slot_ids[1]
		assert len(keys) == 3

		if old_keys:
			assert keys == old_keys
		old_keys = keys


def test_release_transfer_slot(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	prepare_and_cleanup: tuple[list[OpsiDepotserver], list[OpsiClient]],
) -> None:
	depots, clients = prepare_and_cleanup

	backend.config_create(id=TRANSFER_SLOT_CONFIGS[TransferSlotType.OPSICLIENTD_PRODUCT_SYNC], defaultValues=[100])

	redis = redis_client()
	keys = decode_redis_result(redis.keys(f"{config.redis_key('slot')}:*"))
	assert keys == []

	slot_ids = {client.id: [] for client in clients[:2]}
	for client_num in range(2):
		client = clients[client_num]
		test_client.reset_cookies()
		test_client.auth = str(client.id), str(client.opsiHostKey)

		for _ in range(3):
			response = test_client.post(
				"/rpc",
				json={
					"id": 1,
					"method": "depot_acquireTransferSlot",
					"params": [depots[0].id, client.id],
				},
			).json()

			slot_id = response["result"].get("slot_id")
			assert slot_id is not None
			slot_ids[client.id].append(slot_id)

	keys = decode_redis_result(redis.keys(f"{config.redis_key('slot')}:*"))
	assert len(keys) == 6

	released = 0
	for client_num in range(2):
		client = clients[client_num]
		keys = []
		for slot_id in slot_ids[client.id]:
			test_client.reset_cookies()
			test_client.auth = str(client.id), str(client.opsiHostKey)
			response = test_client.post(
				"/rpc",
				json={
					"id": 1,
					"method": "depot_releaseTransferSlot",
					"params": [depots[0].id, client.id, slot_id],
				},
			).json()
			assert response["error"] is None
			released += 1

			keys = decode_redis_result(redis.keys(f"{config.redis_key('slot')}:*"))
			assert len(keys) == 6 - released
			for key in keys:
				assert slot_id not in key

			# Test depot_listTransferSlot
			test_client.reset_cookies()
			test_client.auth = (ADMIN_USER, ADMIN_PASS)
			response = test_client.post(
				"/rpc",
				json={
					"id": 1,
					"method": "depot_listTransferSlot",
					"params": [depots[0].id],
				},
			).json()
			res_slots = response["result"]
			assert len(res_slots) == len(keys)

		for key in keys:
			assert client.id not in key


def test_type_distinction(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	prepare_and_cleanup: tuple[list[OpsiDepotserver], list[OpsiClient]],
) -> None:
	depots, clients = prepare_and_cleanup

	test_client.auth = str(clients[0].id), str(clients[0].opsiHostKey)
	for slot_type in TransferSlotType:
		result = test_client.post(
			"/rpc",
			json={
				"id": 1,
				"method": "depot_acquireTransferSlot",
				"params": [depots[0].id, clients[0].id, None, slot_type],
			},
		).json()
		assert result["error"] is None
		assert result["result"].get("slot_id") is not None
		assert result["result"].get("depot_id") == depots[0].id
		assert result["result"].get("host_id") == clients[0].id
		assert result["result"].get("retry_after") is None
		assert result["result"].get("slot_type") == str(slot_type)

	redis = redis_client()
	assert len(list(redis.scan_iter(f"{config.redis_key('slot')}:{depots[0].id}:*", count=1000))) == len(TransferSlotType)
	for slot_type in TransferSlotType:
		assert len(list(redis.scan_iter(f"{config.redis_key('slot')}:{depots[0].id}:{slot_type}:*", count=1000))) == 1


def test_transfer_slot_session_error(backend: UnprotectedBackend) -> None:  # noqa: F811
	with pytest.raises(BackendPermissionDeniedError) as excinfo:
		backend.depot_acquireTransferSlot(depot="depot1.uib.test", host="client1.uib.test")
		assert "Access denied" in str(excinfo.value)
	with pytest.raises(BackendPermissionDeniedError) as excinfo:
		backend.depot_releaseTransferSlot(depot="depot1.uib.test", host="client1.uib.test", slot_id=TEST_SLOT_ID)
		assert "Access denied" in str(excinfo.value)
