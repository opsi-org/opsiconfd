# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
login tests
"""

import os
import time
import asyncio
from logging import LogRecord

import pytest

from OPSI.Backend.Base.ConfigData import LOG_SIZE_HARD_LIMIT
from opsicommon.logging.constants import LOG_NONE, LOG_ERROR, LOG_WARNING, OPSI_LEVEL_TO_LEVEL

from opsiconfd.logging import (
	Formatter,
	AsyncFileHandler,
	AsyncRotatingFileHandler,
	AsyncRedisLogAdapter,
	RedisLogHandler,
	logger,
	enable_slow_callback_logging,
)

from .utils import config, get_config, clean_redis, test_client, ADMIN_USER, ADMIN_PASS  # pylint: disable=unused-import


def test_log_hard_limit(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	client_id = "logtest.uib.local"
	rpc = {"id": 1, "method": "host_createOpsiClient", "params": [client_id]}
	res = test_client.post("/rpc", verify=False, json=rpc)
	assert res.status_code == 200

	log_line = "log_line_" * 100
	log_data = ""
	expected_size = 0
	while len(log_data) < LOG_SIZE_HARD_LIMIT + len(log_line) * 10:
		if len(log_data) < LOG_SIZE_HARD_LIMIT:
			expected_size = len(log_data)
		log_data += log_line + "\n"

	rpc = {"id": 1, "method": "log_write", "params": ["clientconnect", log_data, client_id, False]}
	res = test_client.post("/rpc", verify=False, json=rpc)
	assert res.status_code == 200
	res = res.json()
	assert res.get("error") is None

	rpc = {"id": 1, "method": "log_read", "params": ["clientconnect", client_id]}
	res = test_client.post("/rpc", verify=False, json=rpc)
	assert res.status_code == 200
	res = res.json()
	assert res.get("error") is None

	assert len(res["result"]) == expected_size

	for line in res["result"][:-1].split("\n"):
		assert line == log_line

	rpc = {"id": 1, "method": "host_delete", "params": [client_id]}
	res = test_client.post("/rpc", verify=False, json=rpc)
	assert res.status_code == 200


@pytest.mark.asyncio
async def test_async_rotating_file_handler_rotation(tmp_path):
	max_log_file_size = 1
	keep_rotated_log_files = 3
	log_file = tmp_path / "test.log"
	for num in (4, 8, 11, "xy"):
		with open(f"{log_file}.{num}", "wb"):
			pass

	AsyncRotatingFileHandler.rollover_check_interval = 1
	handler = AsyncRotatingFileHandler(
		filename=str(log_file), formatter=Formatter("%(message)s"), max_bytes=max_log_file_size, keep_rotated=keep_rotated_log_files
	)
	await asyncio.sleep(1)
	for num in range(5):
		record = LogRecord("test", 3, "pathname", 1, f"message {num}", None, None)
		await handler.emit(record)
		await asyncio.sleep(1)

	await handler.close()
	await asyncio.sleep(1)
	assert os.path.exists(log_file)
	assert os.path.exists(f"{log_file}.1")
	assert os.path.exists(f"{log_file}.2")
	assert os.path.exists(f"{log_file}.3")
	assert len(os.listdir(tmp_path)) == 4


@pytest.mark.asyncio
async def test_async_rotating_file_handler_error_handler(tmp_path):
	log_file = tmp_path / "test.log"

	handled_exception = None
	handled_record = None

	async def handle_file_handler_error(
		file_handler: AsyncFileHandler, record: LogRecord, exception: Exception
	):  # pylint: disable=unused-argument
		nonlocal handled_exception
		handled_exception = exception
		nonlocal handled_record
		handled_record = record

	AsyncRotatingFileHandler.rollover_check_interval = 60
	handler = AsyncRotatingFileHandler(filename=str(log_file), formatter=Formatter("%(message)s"), error_handler=handle_file_handler_error)
	await asyncio.sleep(1)
	await handler.emit(LogRecord("test", 3, "pathname", 1, "message 1", None, None))

	# Closed stream will produce logging error
	await handler.stream.close()
	await asyncio.sleep(1)
	record = LogRecord("test", 3, "pathname", 1, "message 2", None, None)
	await handler.emit(record)

	await asyncio.sleep(1)
	await handler.close()
	await asyncio.sleep(1)

	assert handled_record is record
	assert str(handled_exception) == "I/O operation on closed file."


@pytest.mark.asyncio
async def test_async_redis_log_adapter(tmp_path):
	log_file = tmp_path / "log"
	with get_config({"log_file": str(log_file), "log_level_stderr": LOG_NONE, "log_level_file": LOG_ERROR}):
		redis_log_handler = RedisLogHandler()
		logger.addHandler(redis_log_handler)
		adapter = AsyncRedisLogAdapter()

		for num in range(5):
			logger.error("message %d", num)

		await asyncio.sleep(1)
		await adapter.stop()
		await asyncio.sleep(1)

		with open(log_file, "r", encoding="utf-8") as file:
			lines = file.readlines()
		assert len(lines) == 5
		for idx, line in enumerate(lines):
			assert f"message {idx}" in line


@pytest.mark.asyncio
async def test_slow_callback_logging(tmp_path):
	log_file = tmp_path / "log"
	with get_config({"log_file": str(log_file), "log_level_stderr": LOG_NONE, "log_level_file": LOG_WARNING}):
		redis_log_handler = RedisLogHandler()
		logger.addHandler(redis_log_handler)
		adapter = AsyncRedisLogAdapter()
		logger.setLevel(OPSI_LEVEL_TO_LEVEL[LOG_WARNING])
		await asyncio.sleep(2)

		enable_slow_callback_logging(0.9)
		asyncio.get_event_loop().call_soon(time.sleep, 1)
		await asyncio.sleep(1)

		await adapter.stop()
		await asyncio.sleep(1)

		with open(log_file, "r", encoding="utf-8") as file:
			assert "<Handle sleep(1)> took 1.0" in file.read()
