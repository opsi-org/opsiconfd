# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebroker tests
"""

import aiohttp
import pytest

from .utils import (  # pylint: disable=unused-import
	config, clean_redis, disable_request_warning, create_depot_rpc,
	ADMIN_USER, ADMIN_PASS
)


@pytest.mark.asyncio
async def test_connect_websocket(config):  # pylint: disable=redefined-outer-name
	host_id = "testdepot.uib.gmbh"
	host_key = "92aa768a259dec1856013c4e458507d5"
	create_depot_rpc(config.internal_url, host_id=host_id, host_key=host_key)
	async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(host_id, host_key)) as session:
		websock = await session.ws_connect(f"{config.external_url}/mq", ssl=False)
		await websock.send_bytes(b"test")
		# while True:
		# 	msg = await websock.receive()
		# 	#print(dir(msg))
		# 	print(msg.type)
		# 	if msg.type == aiohttp.WSMsgType.TEXT:
		# 		print(f">>> {msg.data}")
		# 	elif msg.type == aiohttp.WSMsgType.CLOSED:
		# 		break
		# 	elif msg.type == aiohttp.WSMsgType.ERROR:
		# 		break
