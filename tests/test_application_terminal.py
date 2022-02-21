# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.terminal
"""

import os
import uuid
import pytest
from starlette.websockets import WebSocketDisconnect
from starlette.status import WS_1008_POLICY_VIOLATION

from .utils import get_config, clean_redis, test_client, ADMIN_USER, ADMIN_PASS  # pylint: disable=unused-import


def test_connect(test_client):  # pylint: disable=redefined-outer-name
	with pytest.raises(WebSocketDisconnect) as excinfo:
		with test_client.websocket_connect("/admin/terminal/ws"):
			pass
	assert excinfo.value.code == WS_1008_POLICY_VIOLATION

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with pytest.raises(WebSocketDisconnect) as excinfo:
		with test_client.websocket_connect("/admin/terminal/ws?terminal_id=123"):
			pass
	assert excinfo.value.code == WS_1008_POLICY_VIOLATION

	with test_client.websocket_connect("/admin/terminal/ws", params={"terminal_id": str(uuid.uuid4())}):
		pass


def test_shell_config(test_client):  # pylint: disable=redefined-outer-name
	terminal_id = str(uuid.uuid4())
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with get_config({"admin_interface_terminal_shell": "/bin/echo testshell"}):
		with test_client.websocket_connect("/admin/terminal/ws", params={"terminal_id": terminal_id}) as websocket:
			data = websocket.receive()
			print(f"received: >>>{data}<<<")
			assert b"testshell" in data["bytes"]


def test_command(test_client):  # pylint: disable=redefined-outer-name
	terminal_id = str(uuid.uuid4())
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with get_config({"admin_interface_terminal_shell": "/bin/bash"}):
		with test_client.websocket_connect("/admin/terminal/ws", params={"terminal_id": terminal_id}) as websocket:
			data = websocket.receive()
			websocket.send_text("echo test\r\n")
			data = websocket.receive()
			print(f"received: >>>{data}<<<")
			assert b"echo testtest" in data["bytes"].replace(b"\r\n", b"")


def test_params(test_client):  # pylint: disable=redefined-outer-name
	terminal_id = str(uuid.uuid4())
	columns = 30
	lines = 10
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with get_config({"admin_interface_terminal_shell": "/bin/bash"}):
		with test_client.websocket_connect(f"/admin/terminal/ws?terminal_id={terminal_id}&columns={columns}&lines={lines}") as websocket:
			data = websocket.receive()
			websocket.send_text("echo :${COLUMNS}:${LINES}:\r\n")
			data = websocket.receive()
			print(f"received: >>>{data}<<<")
			assert f":{columns}:{lines}:" in data["bytes"].decode("utf-8")


def test_file_upload_auth_and_terminal_id(test_client):  # pylint: disable=redefined-outer-name
	terminal_id = str(uuid.uuid4())
	files = {"file": ("filename.txt", b"file-content")}
	res = test_client.post("/admin/terminal/fileupload", params={"terminal_id": terminal_id}, files=files)
	assert res.status_code == 401

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	res = test_client.post("/admin/terminal/fileupload", files=files)
	assert res.status_code == 422

	res = test_client.post("/admin/terminal/fileupload", params={"terminal_id": terminal_id}, files=files)
	assert res.status_code == 403
	assert "Invalid terminal id" in res.text


def test_file_upload_to_tmp(test_client):  # pylint: disable=redefined-outer-name
	terminal_id = str(uuid.uuid4())
	filename = str(uuid.uuid4())
	files = {"file": (filename, b"file-content")}
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	res = test_client.get("/admin")  # Get a session cookie
	cookie = list(test_client.cookies)[0]
	with test_client.websocket_connect(
		f"/admin/terminal/ws?terminal_id={terminal_id}", headers={"Cookie": f"{cookie.name}={cookie.value}"}
	) as websocket:
		websocket.receive()
		websocket.send_text("cd /tmp\r\n")
		websocket.receive()
		res = test_client.post("/admin/terminal/fileupload", params={"terminal_id": terminal_id}, files=files)
		res.raise_for_status()
		file = os.path.join("/tmp", filename)
		assert os.path.exists(file)
		os.unlink(file)
