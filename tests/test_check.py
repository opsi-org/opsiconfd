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
from unittest import mock

import pytest
from colorama import Fore, Style  # type: ignore[import]
from redis.exceptions import ConnectionError as RedisConnectionError

from opsiconfd.check import check_redis


def test_check_redis() -> None:

	captured_output = io.StringIO()
	sys.stdout = captured_output
	result = check_redis(print_messages=True)
	sys.stdout = sys.__stdout__

	assert (
		captured_output.getvalue()
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
	assert result.get("status") is not None
	assert result["status"] == "ok"

	captured_output = io.StringIO()
	sys.stdout = captured_output
	result = check_redis(print_messages=False)
	sys.stdout = sys.__stdout__

	assert captured_output.getvalue() == ""
	assert result.get("status") is not None
	assert result["status"] == "ok"


def test_check_redis_error() -> None:

	with mock.patch("opsiconfd.utils.get_redis_connection", side_effect=RedisConnectionError("Redis test error")):
		captured_output = io.StringIO()
		sys.stdout = captured_output
		result = check_redis(print_messages=True)
		sys.stdout = sys.__stdout__

		assert (
			captured_output.getvalue()
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
		assert result.get("status") is not None
		assert result["status"] == "error"
		assert result["details"] == "Redis test error"
