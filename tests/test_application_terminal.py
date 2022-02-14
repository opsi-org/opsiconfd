# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.terminal
"""

import pytest
from starlette.websockets import WebSocketDisconnect

from .utils import (  # pylint: disable=unused-import
	clean_redis,
	config,
	get_config,
	test_client,
	ADMIN_USER,
	ADMIN_PASS,
	products_jsonrpc,
	depot_jsonrpc,
	get_product_ordering_jsonrpc,
)


def test_connect(test_client):  # pylint: disable=redefined-outer-name
	with pytest.raises(WebSocketDisconnect) as excinfo:
		with test_client.websocket_connect("/ws/terminal"):
			pass

	assert excinfo.value.code == 401

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client.websocket_connect("/ws/terminal"):
		pass


def test_comand(test_client):  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client.websocket_connect("/ws/terminal") as websocket:
		data = websocket.receive()
		websocket.send_text("echo test\r\n")
		data = websocket.receive()
		assert data["bytes"].startswith(b"echo test\r\ntest\r\n")
