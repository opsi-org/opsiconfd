# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
check tests
"""


import io
import sys
from typing import Any, Callable, Dict
from unittest import mock

from colorama import Fore, Style  # type: ignore[import]
from redis.exceptions import ConnectionError as RedisConnectionError

from opsiconfd.check import check_mysql, check_redis


def captured_function_output(func: Callable, args: Dict[str, Any]) -> Dict[str, Any]:
	captured_output = io.StringIO()
	sys.stdout = captured_output
	result = func(**args)
	sys.stdout = sys.__stdout__

	return {"captured_output": captured_output.getvalue(), "data": result}


def test_check_redis() -> None:

	result = captured_function_output(check_redis, {"print_messages": True})

	assert (
		result.get("captured_output")
		== Fore.WHITE
		+ Style.BRIGHT
		+ "Checking redis..."
		+ Style.RESET_ALL
		+ "\n"
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "Redis is running and Redis-Timeseries is loaded."
		+ Style.RESET_ALL
		+ "\n"
	)
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"

	result = captured_function_output(check_redis, {"print_messages": False})

	assert result.get("captured_output") == ""
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"


def test_check_redis_error() -> None:

	with mock.patch("opsiconfd.utils.get_redis_connection", side_effect=RedisConnectionError("Redis test error")):
		result = captured_function_output(check_redis, {"print_messages": True})
		assert (
			result.get("captured_output")
			== Fore.WHITE
			+ Style.BRIGHT
			+ "Checking redis..."
			+ Style.RESET_ALL
			+ "\n"
			+ Fore.RED
			+ Style.BRIGHT
			+ "Cannot connect to redis!"
			+ Style.RESET_ALL
			+ "\n"
		)
		data = result.get("data", {})
		assert data.get("status") is not None
		assert data["status"] == "error"
		assert data["details"] == "Redis test error"


def test_check_mysql() -> None:

	result = captured_function_output(check_mysql, {"print_messages": True})

	assert (
		result.get("captured_output")
		== Fore.WHITE
		+ Style.BRIGHT
		+ "Checking mysql..."
		+ Style.RESET_ALL
		+ "\n"
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "Connection to mysql is working."
		+ Style.RESET_ALL
		+ "\n"
	)
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"
	assert data["details"] == "Connection to mysql is working."


def test_check_mysql_error() -> None:

	with mock.patch("opsiconfd.check.execute", side_effect=RuntimeError("Command '[...]' failed (1):\nMysql test error")):
		result = captured_function_output(check_mysql, {"print_messages": True})

		assert (
			result.get("captured_output")
			== Fore.WHITE
			+ Style.BRIGHT
			+ "Checking mysql..."
			+ Style.RESET_ALL
			+ "\n"
			+ Fore.RED
			+ Style.BRIGHT
			+ "Could not connect to mysql: Mysql test error"
			+ Style.RESET_ALL
			+ "\n"
		)
		data = result.get("data", {})
		assert data.get("status") is not None
		assert data["status"] == "error"
		assert data["details"] == "Mysql test error"
