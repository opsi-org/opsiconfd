# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.terminal
"""

import os
import time
import uuid
import pytest
from starlette.websockets import WebSocketDisconnect
from starlette.status import WS_1008_POLICY_VIOLATION
import msgpack

from .utils import get_config, clean_redis, test_client, ADMIN_USER, ADMIN_PASS  # pylint: disable=unused-import


def test_connect(test_client):  # pylint: disable=redefined-outer-name
	with pytest.raises(WebSocketDisconnect) as excinfo:
		with test_client.websocket_connect("/admin/terminal/ws"):
			pass
	assert excinfo.value.code == WS_1008_POLICY_VIOLATION

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client.websocket_connect("/admin/terminal/ws"):
		pass


def test_shell_config(test_client):  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with get_config({"admin_interface_terminal_shell": "/bin/echo testshell"}):
		with test_client.websocket_connect("/admin/terminal/ws") as websocket:
			data = websocket.receive()
			print(f"received: >>>{data}<<<")
			assert b"testshell" in data["bytes"]


def test_command(test_client):  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with get_config({"admin_interface_terminal_shell": "/bin/bash"}):
		with test_client.websocket_connect("/admin/terminal/ws") as websocket:
			data = websocket.receive()
			websocket.send_bytes(msgpack.dumps({"type": "terminal-write", "payload": "echo test\r\n"}))
			time.sleep(1)
			data = websocket.receive()
			data = msgpack.loads(data["bytes"])
			print(f"received: >>>{data}<<<")
			assert data["type"] == "terminal-read"
			assert b"echo test" in data["payload"]


def test_params(test_client):  # pylint: disable=redefined-outer-name
	cols = 30
	rows = 10
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with get_config({"admin_interface_terminal_shell": "/bin/bash"}):
		with test_client.websocket_connect(f"/admin/terminal/ws?cols={cols}&rows={rows}") as websocket:
			data = websocket.receive()
			websocket.send_bytes(msgpack.dumps({"type": "terminal-write", "payload": "echo :${COLUMNS}:${LINES}:\r\n"}))
			time.sleep(1)
			data = websocket.receive()
			data = msgpack.loads(data["bytes"])
			print(f"received: >>>{data}<<<")
			assert f":{cols}:{rows}:" in data["payload"].decode("utf-8")


def test_file_upload_to_tmp(test_client):  # pylint: disable=redefined-outer-name
	filename = f"{uuid.uuid4()}.txt"
	content = b"file-content"
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client.websocket_connect("/admin/terminal/ws") as websocket:
		websocket.receive()
		websocket.send_bytes(msgpack.dumps({"type": "terminal-write", "payload": "cd /tmp\r\n"}))
		time.sleep(1)
		websocket.receive()
		ft_msg = {
			"id": str(uuid.uuid4()),
			"type": "file-transfer",
			"payload": {
				"file_id": str(uuid.uuid4()),
				"chunk": 1,
				"name": filename,
				"size": len(content),
				"modified": time.time(),
				"data": content,
				"more_data": False,
			},
		}
		websocket.send_bytes(msgpack.dumps(ft_msg))
		time.sleep(1)
		data = websocket.receive()
		data = msgpack.loads(data["bytes"])
		print(f"received: >>>{data}<<<")
		assert data["type"] == "file-transfer-result"
		assert data["payload"]["file_id"] == ft_msg["payload"]["file_id"]
		assert data["payload"]["error"] is None
		assert data["payload"]["result"]["path"] == filename
		filename = os.path.join("/tmp", filename)
		assert os.path.exists(filename)
		with open(filename, "rb") as file:
			assert file.read() == content
		os.unlink(filename)
