# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
logging tests
"""

import asyncio
import os
import time
from logging import LogRecord
from pathlib import Path
from unittest.mock import patch

import pytest
from opsicommon.logging.constants import (
	LOG_ERROR,
	LOG_NONE,
	LOG_WARNING,
	OPSI_LEVEL_TO_LEVEL,
)

from opsiconfd.logging import (
	AsyncFileHandler,
	AsyncRedisLogAdapter,
	AsyncRotatingFileHandler,
	Formatter,
	RedisLogHandler,
	enable_slow_callback_logging,
	logger,
)

from .utils import (  # pylint: disable=unused-import
	clean_redis,
	get_config,
)


@pytest.mark.asyncio
async def test_async_rotating_file_handler_rotation(tmp_path: Path) -> None:
	max_log_file_size = 1
	keep_rotated_log_files = 3
	log_file = tmp_path / "test.log"
	for num in (4, 8, 11, "xy"):
		with open(f"{log_file}.{num}", "wb"):
			pass

	with patch("opsiconfd.logging.AsyncRotatingFileHandler.rollover_check_interval", 1):
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
async def test_async_rotating_file_handler_error_handler(tmp_path: Path) -> None:
	log_file = tmp_path / "test.log"

	handled_exception = None
	handled_record = None

	async def handle_file_handler_error(
		file_handler: AsyncFileHandler, record: LogRecord, exception: Exception  # pylint: disable=unused-argument
	) -> None:
		nonlocal handled_exception
		handled_exception = exception
		nonlocal handled_record
		handled_record = record

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
async def test_async_redis_log_adapter(tmp_path: Path) -> None:
	log_file = tmp_path / "log"
	# with get_config({"log_file": str(log_file), "log_level_stderr": LOG_NONE, "log_level_file": LOG_ERROR}):
	with get_config({"log_file": str(log_file)}):
		redis_log_handler = RedisLogHandler()
		await asyncio.sleep(1)
		logger.addHandler(redis_log_handler)
		logger.setLevel(OPSI_LEVEL_TO_LEVEL[LOG_ERROR])
		redis_log_handler.setLevel(OPSI_LEVEL_TO_LEVEL[LOG_ERROR])

		adapter = AsyncRedisLogAdapter()
		await asyncio.sleep(1)

		for num in range(5):
			logger.error("message %d", num)

		await asyncio.sleep(1)
		await adapter.stop()
		redis_log_handler.stop()
		await asyncio.sleep(1)

		with open(log_file, "r", encoding="utf-8") as file:
			lines = file.readlines()
		assert len(lines) == 5
		for idx, line in enumerate(lines):
			assert f"message {idx}" in line


@pytest.mark.asyncio
async def test_slow_callback_logging(tmp_path: Path) -> None:
	log_file = tmp_path / "log"
	with get_config({"log_file": str(log_file), "log_level_stderr": LOG_NONE, "log_level_file": LOG_WARNING}):
		redis_log_handler = RedisLogHandler()
		logger.addHandler(redis_log_handler)
		adapter = AsyncRedisLogAdapter()
		logger.setLevel(OPSI_LEVEL_TO_LEVEL[LOG_WARNING])

		await asyncio.sleep(2)
		logger.error("start")
		enable_slow_callback_logging(0.5)
		asyncio.get_event_loop().call_soon(time.sleep, 1)
		logger.error("stop")
		await asyncio.sleep(2)

		await adapter.stop()
		redis_log_handler.stop()
		await asyncio.sleep(1)

		with open(log_file, "r", encoding="utf-8") as file:
			log = file.read()
			assert "<Handle sleep(1)> took 1.0" in log
