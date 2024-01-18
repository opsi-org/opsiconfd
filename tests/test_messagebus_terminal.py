# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.terminal tests
"""

import asyncio
import time
import uuid
from pathlib import Path

import pytest
from opsicommon.messagebus import (
	Error,
	Message,
	TerminalCloseEventMessage,
	TerminalCloseRequestMessage,
	TerminalDataReadMessage,
	TerminalDataWriteMessage,
	TerminalErrorMessage,
	TerminalOpenEventMessage,
	TerminalOpenRequestMessage,
)

from opsiconfd.messagebus.terminal import Terminal, _process_message, start_pty, terminals


def test_start_pty_params(tmp_path: Path) -> None:
	str_path = str(tmp_path)
	cols = 100
	rows = 20
	env = {"TEST": "test"}
	pty = start_pty(shell="/bin/bash", rows=rows, cols=cols, cwd=str_path, env=env)
	time.sleep(2)
	lines = pty.read_nonblocking(size=4096, timeout=3).decode("utf-8").split("\r\n")

	pty.write("pwd\r\n".encode("utf-8"))
	pty.flush()
	time.sleep(2)
	lines = pty.read_nonblocking(size=4096, timeout=3).decode("utf-8").split("\r\n")
	assert lines[0] == "pwd"
	assert lines[1] == str_path

	pty.write("env\r\n".encode("utf-8"))
	pty.flush()
	time.sleep(2)
	lines = pty.read_nonblocking(size=4096, timeout=3).decode("utf-8").split("\r\n")
	assert lines[0] == "env"
	assert "TEST=test" in lines
	assert "TERM=xterm-256color" in lines

	pty.write("stty size\r\n".encode("utf-8"))
	pty.flush()
	time.sleep(2)
	lines = pty.read_nonblocking(size=4096, timeout=3).decode("utf-8").split("\r\n")
	assert lines[0] == "stty size"
	assert lines[1] == f"{rows} {cols}"


def test_start_pty_fail() -> None:
	with pytest.raises(RuntimeError, match="Failed to start pty with shell"):
		start_pty(shell="/will/fail")


async def test_terminal_params() -> None:
	cols = 90
	rows = 25
	terminal_id = str(uuid.uuid4())
	sender = "service_worker:pytest:1"

	assert terminals == {}
	messages: list[Message] = []

	async def send_message(message: Message) -> None:
		print("Message received:", message.to_dict())
		messages.append(message)

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell="/bin/bash", rows=rows, cols=cols
	)
	await _process_message(message=terminal_open_request, send_message=send_message)

	await asyncio.sleep(3)

	assert len(terminals) == 1
	assert isinstance(terminals[terminal_id], Terminal)

	assert isinstance(messages[0], TerminalOpenEventMessage)
	assert messages[0].type == "terminal_open_event"
	assert messages[0].sender == sender
	assert messages[0].channel == "back_channel"
	assert messages[0].terminal_id == terminal_id
	assert messages[0].cols == cols
	assert messages[0].rows == rows

	assert isinstance(messages[1], TerminalDataReadMessage)
	assert messages[1].type == "terminal_data_read"
	assert messages[1].sender == sender
	assert messages[1].channel == "back_channel"
	assert messages[1].terminal_id == terminal_id
	assert messages[1].data

	terminal_data_write_message = TerminalDataWriteMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, data="stty size\r\n".encode("utf-8")
	)
	await _process_message(message=terminal_data_write_message, send_message=send_message)

	await asyncio.sleep(3)
	assert isinstance(messages[2], TerminalDataReadMessage)
	assert messages[2].type == "terminal_data_read"
	assert messages[2].sender == sender
	assert messages[2].channel == "back_channel"
	assert messages[2].terminal_id == terminal_id
	lines = messages[2].data.decode("utf-8").split("\r\n")
	assert lines[0] == "stty size"

	assert isinstance(messages[3], TerminalDataReadMessage)
	lines = messages[3].data.decode("utf-8").split("\r\n")
	assert lines[0] == f"{rows} {cols}"

	# Reopen terminal
	cols = 80
	rows = 30
	messages = []
	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell="/bin/bash", rows=rows, cols=cols
	)
	await _process_message(message=terminal_open_request, send_message=send_message)

	await asyncio.sleep(3)

	assert len(terminals) == 1
	assert isinstance(terminals[terminal_id], Terminal)

	assert isinstance(messages[0], TerminalOpenEventMessage)
	assert messages[0].type == "terminal_open_event"
	assert messages[0].sender == sender
	assert messages[0].channel == "back_channel"
	assert messages[0].terminal_id == terminal_id
	assert messages[0].cols == cols
	assert messages[0].rows == rows

	await asyncio.sleep(3)

	messages = []
	terminal_close_request = TerminalCloseRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id
	)
	await _process_message(message=terminal_close_request, send_message=send_message)
	await asyncio.sleep(3)
	assert isinstance(messages[0], TerminalCloseEventMessage)
	assert messages[0].type == "terminal_close_event"
	assert messages[0].sender == sender
	assert messages[0].channel == "back_channel"
	assert messages[0].terminal_id == terminal_id


async def test_terminal_fail() -> None:
	terminal_id = str(uuid.uuid4())

	messages: list[Message] = []

	async def send_message(message: Message) -> None:
		print("Message received:", message.to_dict())
		messages.append(message)

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell="/fail/shell"
	)
	await _process_message(message=terminal_open_request, send_message=send_message)

	await asyncio.sleep(3)

	assert len(messages) == 2
	assert isinstance(messages[0], TerminalErrorMessage)
	assert messages[0].channel == "back_channel"
	assert messages[0].terminal_id == terminal_id
	assert messages[0].error == Error(
		message=(
			"Failed to create new terminal: Failed to start pty with shell '/fail/shell': "
			"The command was not found or was not executable: /fail/shell."
		)
	)

	assert isinstance(messages[1], TerminalCloseEventMessage)
	assert messages[1].channel == "back_channel"
	assert messages[1].terminal_id == terminal_id

	await asyncio.sleep(1)
	messages = []
	terminal_id = str(uuid.uuid4())

	terminal_open_request = TerminalOpenRequestMessage(
		sender="client", back_channel="back_channel", channel="channel", terminal_id=terminal_id, shell='bash -c "echo exit_1 && exit 1"'
	)
	await _process_message(message=terminal_open_request, send_message=send_message)

	await asyncio.sleep(3)

	assert len(messages) == 3
	assert isinstance(messages[0], TerminalOpenEventMessage)
	assert isinstance(messages[1], TerminalDataReadMessage)
	assert messages[1].data == b"exit_1\r\n"
	assert isinstance(messages[2], TerminalCloseEventMessage)
