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

import msgpack  # type: ignore[import]
import pytest
from starlette.status import WS_1008_POLICY_VIOLATION
from starlette.websockets import WebSocketDisconnect

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	WebSocketMessageReader,
	clean_redis,
	get_config,
	test_client,
)


def test_connect(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	with pytest.raises(WebSocketDisconnect) as excinfo:
		with test_client.websocket_connect("/admin/terminal/ws"):
			pass
	assert excinfo.value.code == WS_1008_POLICY_VIOLATION

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client.websocket_connect("/admin/terminal/ws"):
		pass


def test_shell_config(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with get_config({"admin_interface_terminal_shell": "/bin/echo testshell"}):
		with test_client.websocket_connect("/admin/terminal/ws") as websocket:
			with WebSocketMessageReader(websocket) as reader:
				time.sleep(3)
				payload = "".join([m["payload"].decode("utf-8") for m in reader.get_messages() if m["type"] == "terminal-read"])
				assert "testshell" in payload


def test_command(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with get_config({"admin_interface_terminal_shell": "/bin/bash"}):
		with test_client.websocket_connect("/admin/terminal/ws") as websocket:
			with WebSocketMessageReader(websocket) as reader:
				websocket.send_bytes(msgpack.dumps({"type": "terminal-write", "payload": "echo test\r"}))
				time.sleep(3)
				payload = "".join([m["payload"].decode("utf-8") for m in reader.get_messages() if m["type"] == "terminal-read"])
				assert "test" in payload


def test_params(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	cols = 30
	rows = 10
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with get_config({"admin_interface_terminal_shell": "/bin/bash"}):
		with test_client.websocket_connect(f"/admin/terminal/ws?cols={cols}&rows={rows}") as websocket:
			with WebSocketMessageReader(websocket) as reader:
				websocket.send_bytes(msgpack.dumps({"type": "terminal-write", "payload": "echo :${COLUMNS}:${LINES}:\r"}))
				time.sleep(3)
				payload = "".join([m["payload"].decode("utf-8") for m in reader.get_messages() if m["type"] == "terminal-read"])
				assert f":{cols}:{rows}:" in payload


def test_file_upload_to_tmp(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	filename = f"{uuid.uuid4()}.txt"
	content = b"file-content"
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client.websocket_connect("/admin/terminal/ws") as websocket:
		with WebSocketMessageReader(websocket) as reader:
			websocket.send_bytes(msgpack.dumps({"type": "terminal-write", "payload": "cd /tmp\r"}))
			time.sleep(3)
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
			time.sleep(3)

			msg = list(reader.get_messages())[-1]
			assert isinstance(msg, dict)
			assert msg["type"] == "file-transfer-result"
			assert msg["payload"]["file_id"] == ft_msg["payload"]["file_id"]  # type: ignore[index]
			assert msg["payload"]["error"] is None
			assert msg["payload"]["result"]["path"] == filename
			filename = os.path.join("/tmp", filename)
			assert os.path.exists(filename)
			with open(filename, "rb") as file:
				assert file.read() == content
			os.unlink(filename)
