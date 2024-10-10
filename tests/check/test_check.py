# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import json
from datetime import datetime, timedelta
from unittest import mock

import pytest
from _pytest.capture import CaptureFixture
from MySQLdb import OperationalError  # type: ignore[import]
from opsicommon.objects import ConfigState, OpsiClient
from redis.exceptions import ConnectionError as RedisConnectionError

from opsiconfd.check.cache import check_cache_clear
from opsiconfd.check.cli import console_health_check
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.check.main import (
	health_check,
)
from opsiconfd.check.opsipackages import get_enabled_hosts
from opsiconfd.check.register import register_checks
from opsiconfd.config import get_configserver_id
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	get_config,
	sync_clean_redis,
	test_client,
)

DEPRECATED_METHOD = "getClientIds_list"


def test_upgrade_issue() -> None:
	class TestCheck(Check):
		id = "test_upgrade_issue"

	class TestCheck1(Check):
		id = "test_upgrade_issue:5.1"
		partial_check = True
		upgrade_issue = "5.1"

	class TestCheck2(Check):
		partial_check = True
		id = "test_upgrade_issue:5.0"

	test_check_1 = TestCheck1()
	test_check_2 = TestCheck2()
	test_check = TestCheck(partial_checks=[test_check_1, test_check_2])

	result = CheckResult(check=test_check)
	partial_result = CheckResult(check=test_check_1, check_status=CheckStatus.WARNING, upgrade_issue="5.0")
	print(id(partial_result))
	result.add_partial_result(partial_result)
	partial_result = CheckResult(check=test_check_2, check_status=CheckStatus.WARNING, upgrade_issue="5.1")
	print(id(partial_result))
	result.add_partial_result(partial_result)
	assert result.check_status == CheckStatus.WARNING
	assert result.upgrade_issue == "5.0"


def test_health_check() -> None:
	sync_clean_redis()
	register_checks()
	results = list(health_check())
	assert len(results) == 20
	for result in results:
		print(result.check.id, result.check_status)
		assert result.check_status


# def test_checks_and_skip_checks() -> None:
# 	register_checks()
# 	with get_config({"checks": ["redis", "mysql", "ssl"]}):
# 		list_of_checks = list(health_check())
# 		assert len(list_of_checks) == 3

# 	with get_config({"skip_checks": ["redis", "mysql", "ssl"]}):
# 		list_of_checks = list(health_check())
# 		assert len(list_of_checks) == 17


def test_check_opsi_config_checkmk(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	register_checks()
	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [True]]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_manager.get("opsi_config").run(clear_cache=True)
	checkmk = result.to_checkmk()
	assert checkmk.startswith("0")
	assert result.check.name in checkmk
	assert "No issues found in the opsi configuration." in checkmk
	assert "Configuration opsiclientd.global.verify_server_cert is set to default." in checkmk

	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [False]]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_manager.get("opsi_config").run(clear_cache=True)
	checkmk = result.to_checkmk()
	assert checkmk.startswith("1")
	assert "1 issue(s) found." in checkmk
	assert "Configuration opsiclientd.global.verify_server_cert is set to [False] - default is [True]." in checkmk

	rpc = {"id": 1, "method": "config_delete", "params": ["opsiclientd.global.verify_server_cert"]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_manager.get("opsi_config").run(clear_cache=True)
	checkmk = result.to_checkmk()
	assert checkmk.startswith("2")
	assert "1 issue(s) found." in checkmk
	assert "Configuration opsiclientd.global.verify_server_cert does not exist." in checkmk


@pytest.mark.parametrize("format", ("cli", "json", "checkmk"))
def test_check_console_health_check(capsys: CaptureFixture[str], format: str) -> None:
	register_checks()
	with get_config({"upgrade_check": False, "documentation": False, "detailed": True, "format": format}):
		console_health_check()
		captured = capsys.readouterr()
		if format == "json":
			data = json.loads(captured.out)
			assert isinstance(data, dict)
			assert len(data) > 10
			assert data["check_status"]
			assert data["summary"]
			assert isinstance(data["system_repositories"], dict)
			assert data["system_repositories"]["check"]
			test_check = Check(**data["system_repositories"]["check"])
			assert test_check.id
			assert test_check.description
		elif format == "checkmk":
			services = captured.out.split("\n")
			assert len(services) > 10
			status, _ = services[0].split(" ", 1)
			assert 0 <= int(status) <= 2
		else:
			assert "● Redis" in captured.out


def test_check_downtime(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client = OpsiClient(id="test-check-client-1.opsi.test")
	client.setDefaults()
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"id": 1,
		"method": "host_getIdents",
		"params": [],
	}
	res = test_client.post("/rpc", json=rpc)
	hosts = res.json().get("result")

	# all host should be enabled
	enabled_hosts = get_enabled_hosts()
	assert hosts == enabled_hosts

	# set downtime for client 1 for tomorrow and check if it is disabled
	tomorrow = datetime.now() + timedelta(days=1)
	downtime = ConfigState(configId="opsi.check.downtime.end", objectId=client.id, values=[tomorrow.isoformat()])
	rpc = {
		"id": 1,
		"method": "configState_updateObjects",
		"params": [[downtime.to_json()]],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	enabled_hosts = get_enabled_hosts()
	assert len(hosts) > len(enabled_hosts)

	# set downtime for client 1 from yesterday to tomorrow and check if it is disabled
	yesterday = datetime.now() - timedelta(days=1)
	downtime = ConfigState(configId="opsi.check.downtime.end", objectId=client.id, values=[tomorrow.isoformat()])
	rpc = {
		"id": 1,
		"method": "configState_updateObjects",
		"params": [[downtime.to_json()]],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	enabled_hosts = get_enabled_hosts()
	assert len(hosts) > len(enabled_hosts)

	# set downtime for client 1 from tomorrow to 2 days from now and check if it is enabled
	two_days = datetime.now() + timedelta(days=2)
	downtime = ConfigState(configId="opsi.check.downtime.end", objectId=client.id, values=[two_days.isoformat()])
	rpc = {
		"id": 1,
		"method": "configState_updateObjects",
		"params": [[downtime.to_json()]],
	}
	downtime = ConfigState(configId="opsi.check.downtime.start", objectId=client.id, values=[tomorrow.isoformat()])
	rpc = {
		"id": 1,
		"method": "configState_updateObjects",
		"params": [[downtime.to_json()]],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	enabled_hosts = get_enabled_hosts()
	assert len(hosts) == len(enabled_hosts)

	rpc = {
		"id": 1,
		"method": "configState_delete",
		"params": ["opsi.check.downtime.start", client.id],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	# set downtime for client 1 for yesterday and check if it is enabled
	downtime = ConfigState(configId="opsi.check.downtime.end", objectId=client.id, values=[yesterday.isoformat()])
	rpc = {
		"id": 1,
		"method": "configState_updateObjects",
		"params": [[downtime.to_json()]],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	enabled_hosts = get_enabled_hosts()
	assert len(hosts) == len(enabled_hosts)

	# set opsi.check.enabled to false for client 1 and check if it is disabled
	disable = ConfigState(configId="opsi.check.enabled", objectId=client.id, values=[False])
	rpc = {
		"id": 1,
		"method": "configState_updateObjects",
		"params": [[disable.to_json()]],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	enabled_hosts = get_enabled_hosts()
	assert len(hosts) > len(enabled_hosts)

	# set opsi.check.enabled to true for client 1 and check if it is enabled
	enable = ConfigState(configId="opsi.check.enabled", objectId=client.id, values=[True])
	rpc = {
		"id": 1,
		"method": "configState_updateObjects",
		"params": [[enable.to_json()]],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	enabled_hosts = get_enabled_hosts()
	assert len(hosts) == len(enabled_hosts)

	# set opsi.check.enabled to false for config server and check if all hosts are disabled
	# delete downtime and enable config for client 1
	config_server = get_configserver_id()
	disable_server = ConfigState(configId="opsi.check.enabled", objectId=config_server, values=[False])
	rpc = {
		"id": 1,
		"method": "configState_updateObjects",
		"params": [[disable_server.to_json()]],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	rpc = {
		"id": 1,
		"method": "configState_delete",
		"params": ["opsi.check.enabled", client.id],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	rpc = {
		"id": 1,
		"method": "configState_delete",
		"params": ["opsi.check.downtime.end", client.id],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	rpc = {
		"id": 1,
		"method": "configState_delete",
		"params": ["opsi.check.downtime.start", client.id],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	enabled_hosts = get_enabled_hosts()
	assert len(enabled_hosts) == 0

	# delete config state for config server and check if all hosts are enabled
	rpc = {
		"id": 1,
		"method": "configState_delete",
		"params": ["opsi.check.enabled", config_server],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	enabled_hosts = get_enabled_hosts()
	assert hosts == enabled_hosts


def test_check_cache(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	register_checks()
	sync_clean_redis()
	check_cache_clear("all")
	# backup check should fail. No backup was created.
	check_cache_clear("opsi_backup")
	result = check_manager.get("opsi_backup").run()
	assert result.check_status == CheckStatus.ERROR

	with mock.patch(
		"opsiconfd.check.mysql.MySQLConnection.connect",
		side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'),
	):
		result = check_manager.get("mysql").run()
		assert result.check_status == CheckStatus.ERROR

	with mock.patch("opsiconfd.check.redis.redis_client", side_effect=RedisConnectionError("Redis test error")):
		result = check_manager.get("redis").run()
		assert result.check_status == CheckStatus.ERROR

	# Create a backup
	rpc = {"id": 1, "method": "service_createBackup", "params": [False, False, False]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	# Redis and mysql check should fail. Backup cache should be reset after calling create backup.
	result = check_manager.get("redis").run()
	assert result.check_status == CheckStatus.ERROR
	result = check_manager.get("opsi_backup").run()
	assert result.check_status == CheckStatus.OK
	result = check_manager.get("mysql").run()
	assert result.check_status == CheckStatus.ERROR

	# Clear backup cache
	check_cache_clear("opsi_backup")

	# Backup check should pass. A backup was created. Mysql check should fail. Cache is not cleared.
	result = check_manager.get("redis").run()
	assert result.check_status == CheckStatus.ERROR
	result = check_manager.get("opsi_backup").run()
	assert result.check_status == CheckStatus.OK
	result = check_manager.get("mysql").run()
	assert result.check_status == CheckStatus.ERROR

	# Clear cache. Backup and mysql check should pass.
	check_cache_clear("all")
	result = check_manager.get("redis").run()
	assert result.check_status == CheckStatus.OK
	result = check_manager.get("opsi_backup").run()
	assert result.check_status == CheckStatus.OK
	result = check_manager.get("mysql").run()
	assert result.check_status == CheckStatus.OK
