# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test websocket
"""

import time
from unittest.mock import patch

import msgpack  # type: ignore[import]

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	WebSocketMessageReader,
	clean_redis,
	test_client,
)


def test_websocket_keep_session_valid(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	with patch("opsiconfd.session.OPSISession._store_interval", 1):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		headers = {"x-opsi-session-lifetime": "5"}
		response = test_client.get("/session/authenticated", headers=headers)
		assert response.status_code == 200
		cookie = list(test_client.cookies.jar)[0]
		headers["Cookie"] = f"{cookie.name}={cookie.value}"

		with test_client.websocket_connect("/ws/echo?set_cookie_interval=1", headers=headers) as websocket:
			received = []
			with WebSocketMessageReader(websocket) as reader:
				data = msgpack.dumps({"type": "data"})
				for _ in range(10):
					websocket.send_bytes(data)
					time.sleep(1)
				received = list(reader.get_messages())

			assert len([msg for msg in received if msg["type"] == "data"]) >= 7  # type: ignore[call-overload]
			set_cookie = [msg for msg in received if msg["type"] == "set-cookie"]  # type: ignore[call-overload]
			assert len(set_cookie) >= 7
			for msg in set_cookie:
				assert msg["payload"].endswith("Max-Age=5")  # type: ignore[call-overload]

		# Test if session is valid
		test_client.auth = None
		response = test_client.get("/session/authenticated", headers=headers)
		assert response.status_code == 200

		time.sleep(6)
		response = test_client.get("/session/authenticated", headers=headers)
		assert response.status_code == 401
