# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebroker tests
"""

from .utils import (  # pylint: disable=unused-import
	clean_redis, disable_request_warning, depot_jsonrpc,
	ADMIN_USER, ADMIN_PASS
)


def test_connect_websocket(test_client):  # pylint: disable=redefined-outer-name
	host_id = "testdepot.uib.gmbh"
	host_key = "92aa768a259dec1856013c4e458507d5"
	with depot_jsonrpc(test_client, "", host_id=host_id, host_key=host_key):
		websock = test_client.websocket_connect("/mq")
		websock.send_bytes(b"test")
		# while True:
		# 	msg = websock.receive()
		# 	#print(dir(msg))
		# 	print(msg.type)
		# 	if msg.type == aiohttp.WSMsgType.TEXT:
		# 		print(f">>> {msg.data}")
		# 	elif msg.type == aiohttp.WSMsgType.CLOSED:
		# 		break
		# 	elif msg.type == aiohttp.WSMsgType.ERROR:
		# 		break
