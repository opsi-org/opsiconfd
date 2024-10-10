# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

from unittest import mock

from redis.exceptions import ConnectionError as RedisConnectionError
from rich.console import Console

from opsiconfd.check.cli import process_check_result
from opsiconfd.check.common import check_manager
from opsiconfd.check.redis import RedisCheck
from tests.utils import (  # noqa: F401
	captured_function_output,
	cleanup_checks,  # noqa: F401
)
from tests.utils import (
	config as test_config,  # noqa: F401
)


def register_redis_check() -> None:
	check_manager.register(RedisCheck())


def test_check_redis() -> None:
	register_redis_check()

	console = Console(log_time=False, force_terminal=False, width=1000)
	result = check_manager.get("redis").run(clear_cache=True)
	captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
	assert "Redis: OK" in captured_output
	assert "The connection to the Redis server does work. " in captured_output
	assert "RedisTimeSeries version " in captured_output
	assert "Redis memory usage is OK" in captured_output
	assert result.check_status == "ok"


def test_check_redis_connection_error() -> None:
	register_redis_check()
	console = Console(log_time=False, force_terminal=False, width=1000)

	with mock.patch("opsiconfd.check.redis.redis_client", side_effect=RedisConnectionError("Redis test error")):
		result = check_manager.get("redis").run(clear_cache=True)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		assert "Cannot connect to Redis" in captured_output
		assert result.check_status == "error"
		assert result.message == "Cannot connect to Redis: Redis test error"


def test_check_redis_memory_warning() -> None:
	register_redis_check()
	console = Console(log_time=False, force_terminal=False, width=1000)

	with mock.patch("opsiconfd.check.redis.MEMORY_USAGE_WARN", 1):
		result = check_manager.get("redis").run(clear_cache=True)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
		assert "WARNING - Redis memory usage is high" in captured_output


def test_check_redis_memory_error() -> None:
	register_redis_check()
	console = Console(log_time=False, force_terminal=False, width=1000)
	with mock.patch("opsiconfd.check.redis.MEMORY_USAGE_ERR", 1):
		result = check_manager.get("redis").run(clear_cache=True)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
		assert "ERROR - Redis memory usage is too high" in captured_output
