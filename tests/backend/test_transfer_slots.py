# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav tests
"""

from unittest.mock import MagicMock, patch, Mock


from opsiconfd.backend.rpc.general import TRANSFER_SLOT_CONFIG, TransferSlot

from ..utils import ADMIN_PASS, ADMIN_USER, OpsiconfdTestClient, test_client, client_jsonrpc, backend  # pylint: disable=unused-import


# Acquiring a transfer slot when there are available slots.
def test_acquire_transfer_slot_available_slots(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	# Mock the session
	session_mock = Mock()
	session_mock.authenticated = True
	session_mock.host = None
	session_mock.client_addr = "127.0.0.1"
	patch("opsiconfd.contextvar_client_session.get", return_value=session_mock)

	# Mock the redis client
	redis_mock = Mock()
	redis_mock.keys.return_value = []
	patch("opsiconfd.redis.redis_client", return_value=redis_mock)

	# Mock the config state
	config_state_mock = Mock()
	config_state_mock.getValues.return_value = {}
	patch("opsiconfd.RPCGeneralMixin.configState_getValues", return_value=config_state_mock)

	# Call the method under test
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client_id = "test-client-dom.opsi.org"
	host_key = "76768a28560d5924e4587dec5913c501"
	with client_jsonrpc(test_client, "", client_id, host_key):
		rpc = {"id": 1, "method": "service_acquireTransferSlot", "params": ["depot1.uib.test"]}
		res = test_client.post("/rpc", json=rpc)
	result = res.json()

	# Assert the result
	assert result["result"].get("depot_id") == "depot1.uib.test"
	assert result["result"].get("retry_after") is None
