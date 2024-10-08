# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import time
from datetime import datetime, timezone
from unittest import mock
from warnings import catch_warnings, simplefilter

from rich.console import Console

from opsiconfd.check.cli import process_check_result
from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.check.jsonrpc import deprecated_calls_check
from opsiconfd.config import config
from opsiconfd.redis import redis_client
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	captured_function_output,
	cleanup_checks,
	sync_clean_redis,
	test_client,
)

DEPRECATED_METHOD = "getClientIds_list"


def test_check_deprecated_calls(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	check_manager.register(deprecated_calls_check)

	sync_clean_redis()
	console = Console(log_time=False, force_terminal=False, width=1000)
	result = check_manager.get("deprecated_calls").run(use_cache=False)
	captured_output = captured_function_output(process_check_result, result=result, console=console)
	assert "No deprecated method calls found." in captured_output
	assert result.check_status == CheckStatus.OK

	rpc = {"id": 1, "method": DEPRECATED_METHOD, "params": []}
	current_dt = datetime.now(timezone.utc)
	with mock.patch("opsiconfd.application.jsonrpc.AWAIT_STORE_RPC_INFO", True), catch_warnings():
		simplefilter("ignore")
		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	assert res.status_code == 200
	time.sleep(3)
	result = check_manager.get("deprecated_calls").run(use_cache=False)

	# print(result)
	assert result.check_status == CheckStatus.WARNING
	assert len(result.partial_results) == 1
	partial_result = result.partial_results[0]
	# print(partial_result)
	assert partial_result.details["method"] == DEPRECATED_METHOD
	assert partial_result.details["calls"] == "1"
	assert partial_result.details["last_call"]
	assert partial_result.details["drop_version"] == "4.4"
	assert partial_result.upgrade_issue == "4.4"
	last_call_dt = datetime.fromisoformat(partial_result.details["last_call"]).astimezone(timezone.utc)
	assert (last_call_dt - current_dt).total_seconds() < 3
	assert isinstance(partial_result.details["applications"], list)
	assert partial_result.details["applications"] == ["testclient"]

	captured_output = captured_function_output(process_check_result, result=result, console=console, check_version="4.4", detailed=True)
	assert "The method will be dropped with opsiconfd version 4.4" in captured_output

	# test key expires and method is removed from set
	redis_prefix_stats = config.redis_key("stats")
	redis = redis_client()
	methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
	assert len(methods) == 1
	redis.expire(f"{redis_prefix_stats}:rpcs:deprecated:{DEPRECATED_METHOD}:count", 1)
	time.sleep(5)
	result = check_manager.get("deprecated_calls").run(use_cache=False)
	assert result.check_status == CheckStatus.OK

	methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
	assert len(methods) == 0
