# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav tests
"""
from typing import Generator
from unittest.mock import Mock, patch

import pytest

from opsiconfd.backend.rpc.general import TRANSFER_SLOT_CONFIG, TRANSFER_SLOT_MAX, TransferSlot
from opsiconfd.backend.rpc.main import UnprotectedBackend

from ..utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	backend,
	client_jsonrpc,
	sync_clean_redis,
	test_client,
)


@pytest.fixture(autouse=True)
def clean_configs_and_objects(backend: UnprotectedBackend) -> Generator:  # pylint: disable=redefined-outer-name
	sync_clean_redis()

	backend.configState_delete(configId=TRANSFER_SLOT_CONFIG, objectId="*")
	backend.config_delete(id=TRANSFER_SLOT_CONFIG)

	yield

	sync_clean_redis()
	backend.configState_delete(configId=TRANSFER_SLOT_CONFIG, objectId="*")
	backend.config_delete(id=TRANSFER_SLOT_CONFIG)


# Acquiring a transfer slot when there are available slots.
def test_acquire_transfer_slot_available_slots(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	# Mock the session
	session_mock = Mock()
	session_mock.authenticated = True
	session_mock.host = None
	session_mock.client_addr = "127.0.0.1"
	patch("opsiconfd.contextvar_client_session.get", return_value=session_mock)

	# Call the method under test
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client_id = "test-client-dom.opsi.org"
	host_key = "76768a28560d5924e4587dec5913c501"
	with client_jsonrpc(test_client, "", client_id, host_key):
		rpc = {"id": 1, "method": "service_acquireTransferSlot", "params": ["depot1.uib.test"]}
		res = test_client.post("/rpc", json=rpc)
	result = res.json()

	# Assert the result
	assert result["result"].get("slot_id") is not None
	assert result["result"].get("depot_id") == "depot1.uib.test"
	assert result["result"].get("retry_after") is None


def test_acquire_transfer_slot_with_slot_id(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	# Mock the session
	session_mock = Mock()
	session_mock.authenticated = True
	session_mock.host = None
	session_mock.client_addr = "127.0.0.1"
	patch("opsiconfd.contextvar_client_session.get", return_value=session_mock)

	# Call the method under test
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client_id = "test-client-dom.opsi.org"
	host_key = "76768a28560d5924e4587dec5913c501"
	for i in range(12):  # pylint: disable=unused-variable
		with client_jsonrpc(test_client, "", client_id, host_key):
			rpc = {"id": 1, "method": "service_acquireTransferSlot", "params": ["depot1.uib.test", "depot1.uib.test-slot1"]}
			res = test_client.post("/rpc", json=rpc)
		result = res.json()

		# Assert the result
		assert result["result"].get("slot_id") == "depot1.uib.test-slot1"
		assert result["result"].get("depot_id") == "depot1.uib.test"
		assert result["result"].get("retry_after") is None


def test_acquire_transfer_slot_max(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	# Mock the session
	session_mock = Mock()
	session_mock.authenticated = True
	session_mock.host = None
	session_mock.client_addr = "127.0.0.1"
	patch("opsiconfd.contextvar_client_session.get", return_value=session_mock)

	for i in range(TRANSFER_SLOT_MAX):
		print(i)
		# Call the method under test
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		client_id = "test-client-dom.opsi.org"
		host_key = "76768a28560d5924e4587dec5913c501"
		with client_jsonrpc(test_client, "", client_id, host_key):
			rpc = {"id": 1, "method": "service_acquireTransferSlot", "params": ["depot1.uib.test", f"depot1.uib.test-slot{i}"]}
			res = test_client.post("/rpc", json=rpc)
		result = res.json()

		# Assert the result
		assert result["result"].get("slot_id") == f"depot1.uib.test-slot{i}"
		assert result["result"].get("depot_id") == "depot1.uib.test"
		assert result["result"].get("retry_after") is None

	with client_jsonrpc(test_client, "", client_id, host_key):
		rpc = {"id": 1, "method": "service_acquireTransferSlot", "params": ["depot1.uib.test", "depot1.uib.test-slot10"]}
		res = test_client.post("/rpc", json=rpc)
	result = res.json()

	# Assert the result
	assert result["result"].get("slot_id") is None
	assert result["result"].get("depot_id") is None
	assert result["result"].get("retry_after") is not None


def test_create_transfer_slot_with_depot_id() -> None:
	depot_id = "depot1"
	transfer_slot = TransferSlot(depot_id)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.slot_id is not None
	assert transfer_slot.retry_after is None


def test_create_transfer_slot_with_depot_id_and_slot_id() -> None:
	depot_id = "depot1"
	slot_id = "slot1"
	transfer_slot = TransferSlot(depot_id, slot_id)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.slot_id == slot_id
	assert transfer_slot.retry_after is None


def test_create_transfer_slot_with_depot_id_slot_id_and_retry_after() -> None:
	depot_id = "depot1"
	slot_id = "slot1"
	retry_after = 60
	transfer_slot = TransferSlot(depot_id, slot_id, retry_after)
	assert transfer_slot.depot_id == depot_id
	assert transfer_slot.slot_id == slot_id
	assert transfer_slot.retry_after == retry_after


def test_acquire_transfer_slot_session_error(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = ("fake-user", "fake-pass")
	res = test_client.post("/rpc", json={"id": 1, "method": "service_acquireTransferSlot", "params": ["depot1.uib.test"]})
	result = res.json()

	assert result["result"] is None
	assert result["error"] == "Authentication error"
