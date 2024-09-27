# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import time
from unittest import mock

from MySQLdb import OperationalError  # type: ignore[import]
from opsicommon.objects import OpsiClient
from rich.console import Console

from opsiconfd.check.cache import check_cache_clear
from opsiconfd.check.cli import process_check_result
from opsiconfd.check.common import CheckStatus, check_manager
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import (  # noqa: F401
	ACL_CONF_41,
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	captured_function_output,
	clean_mysql,
	cleanup_checks,  # noqa: F401
	get_config,
	get_opsi_config,
	sync_clean_redis,
	test_client,
)
from tests.utils import (
	config as test_config,  # noqa: F401
)

DEPRECATED_METHOD = "getClientIds_list"


def register_mysql_check() -> None:
	from opsiconfd.check.mysql import MysqlCheck, UniqueHardwareAddressesCheck

	check_manager.register(MysqlCheck(), UniqueHardwareAddressesCheck())


def test_check_mysql() -> None:
	register_mysql_check()
	console = Console(log_time=False, force_terminal=False, width=1000)
	with mock.patch("opsiconfd.check.mysql.MAX_ALLOWED_PACKET", 1):
		result = check_manager.get("mysql").run(use_cache=False)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		assert "No MySQL issues found." in captured_output
		assert result.check_status == "ok"
		assert result.message == "No MySQL issues found."


def test_check_mysql_error() -> None:
	register_mysql_check()
	with mock.patch(
		"opsiconfd.check.mysql.MySQLConnection.connect",
		side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'),
	):
		console = Console(log_time=False, force_terminal=False, width=1000)
		result = check_manager.get("mysql").run(use_cache=False)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		assert '2005 - "Unknown MySQL server host bla (-3)"' in captured_output
		assert result.check_status == "error"
		assert result.message == 'Could not connect to MySQL Server: 2005 - "Unknown MySQL server host bla (-3)"'

	check_cache_clear("all")
	with mock.patch("opsiconfd.check.mysql.MAX_ALLOWED_PACKET", 1_000_000_000):
		result = check_manager.get("mysql").run(use_cache=False)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
		assert "is too small (should be at least 1000000000)" in captured_output


def test_check_unique_hardware_addresses(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	register_mysql_check()
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client = OpsiClient(id="test-check-client-1.opsi.test")
	client.setDefaults()
	client.hardwareAddress = "00:00:00:00:00:00"
	client2 = OpsiClient(id="test-check-client-2.opsi.test")
	client2.setDefaults()
	client2.hardwareAddress = "00:00:00:00:00:00"

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client.to_hash(), client2.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# result = check_unique_hardware_addresses(CheckRegistry().get("unique_hardware_addresses").result)
	result = check_manager.get("unique_hardware_addresses").run(use_cache=False)
	assert result.check_status == CheckStatus.ERROR

	client2.hardwareAddress = "00:00:00:00:00:01"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_updateObjects", "params": [[client2.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	time.sleep(1)

	result = check_manager.get("unique_hardware_addresses").run(use_cache=False)
	assert result.check_status == CheckStatus.OK
