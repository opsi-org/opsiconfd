# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
Tests for the opsiconfd monitoring module
"""

import json
import time
from datetime import datetime, timedelta
from typing import Any, Generator
from unittest import mock

import pytest

from opsiconfd.application.monitoring.check_locked_products import check_locked_products
from opsiconfd.application.monitoring.check_opsi_disk_usage import check_opsi_disk_usage
from opsiconfd.application.monitoring.check_plugin_on_client import (
	check_plugin_on_client,
)
from opsiconfd.application.monitoring.check_short_product_status import (
	check_short_product_status,
)
from opsiconfd.config import get_depotserver_id
from opsiconfd.utils import DiskUsage
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	MySQLConnection,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	config,
	create_depot_jsonrpc,
	delete_mysql_data,
	get_config,
	test_client,
)

MONITORING_CHECK_DAYS = 31

test_data: tuple[tuple[Any, Any, Any, Any], ...] = (
	(
		{"capacity": 107374182400, "available": 21474836480, "used": 85899345920, "usage": 0.80},
		"workbench",
		{},
		{"state": 0, "message": "OK: DiskUsage from ressource 'workbench' is ok. (available:  20.00GB)."},
	),
	(
		{"capacity": 107374182400, "available": 1073741824, "used": 106300440576, "usage": 0.99},
		"workbench",
		{},
		{"state": 2, "message": "CRITICAL: DiskUsage from ressource: 'workbench' is critical (available: 1.00GB)."},
	),
	(
		{"capacity": 107374182400, "available": 5368709120, "used": 102005473280, "usage": 0.95},
		"workbench",
		{},
		{"state": 1, "message": "WARNING: DiskUsage warning from ressource: 'workbench' (available: 5.00GB)."},
	),
	(
		{"capacity": 107374182400, "available": 21474836480, "used": 85899345920, "usage": 0.80},
		"workbench",
		{"warning": "30G", "critical": "10G"},
		{"state": 1, "message": "WARNING: DiskUsage warning from ressource: 'workbench' (available: 20.00GB)."},
	),
	(
		{"capacity": 107374182400, "available": 21474836480, "used": 85899345920, "usage": 0.80},
		"workbench",
		{"warning": "30G", "critical": "20G"},
		{"state": 2, "message": "CRITICAL: DiskUsage from ressource: 'workbench' is critical (available: 20.00GB)."},
	),
	(
		{"capacity": 107374182400, "available": 21474836480, "used": 85899345920, "usage": 0.80},
		["depot", "workbench"],
		{"warning": "30G", "critical": "20G"},
		{
			"state": 2,
			"message": (
				"CRITICAL: DiskUsage from ressource: 'depot' is critical (available: 20.00GB). "
				"DiskUsage from ressource: 'workbench' is critical (available: 20.00GB)."
			),
		},
	),
	(
		{"capacity": 107374182400, "available": 21474836480, "used": 85899345920, "usage": 0.80},
		["depot", "workbench"],
		{"warning": "30%", "critical": "20%"},
		{
			"state": 2,
			"message": (
				"CRITICAL: DiskUsage from ressource: 'depot' is critical (available: 20.00%). "
				"DiskUsage from ressource: 'workbench' is critical (available: 20.00%)."
			),
		},
	),
	(
		{"capacity": 107374182400, "available": 21474836480, "used": 85899345920, "usage": 0.80},
		"depot",
		{"warning": "10%", "critical": "5%"},
		{"state": 0, "message": "OK: DiskUsage from ressource: 'depot' is ok. (available: 20.00%)."},
	),
	(
		{"capacity": 107374182400, "available": 21474836480, "used": 85899345920, "usage": 0.80},
		"not-a-resource",
		{"warning": "10%", "critical": "5%"},
		{"state": 3, "message": "UNKNOWN: No disk usage results, nothing to check."},
	),
	(
		{"capacity": 107374182400, "available": 21474836480, "used": 85899345920, "usage": 0.80},
		None,
		{"warning": "10%", "critical": "5%"},
		{
			"state": 0,
			"message": (
				"OK: DiskUsage from ressource: 'depot' is ok. (available: 20.00%). "
				"DiskUsage from ressource: 'repository' is ok. (available: 20.00%). "
				"DiskUsage from ressource: 'workbench' is ok. (available: 20.00%)."
			),
		},
	),
)


@pytest.fixture(autouse=True)
def create_check_data(test_client: OpsiconfdTestClient, config: Config) -> Generator[None, None, None]:  # noqa: F811  # noqa: F811
	delete_mysql_data()

	mysql = MySQLConnection()

	now = datetime.now()
	with mysql.connection():
		with mysql.session() as session:
			res = session.execute("SELECT * FROM HOST WHERE type != 'OpsiClient'").fetchall()
			print("Server objects in MySQL:", res)

			# Product
			for idx in range(5):
				session.execute(
					"INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority, setupScript, uninstallScript) VALUES "
					f'("pytest-prod-{idx}", "1.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT {idx}", 60+{idx},'
					' "setup.opsiscript", "uninstall.opsiscript");'
				)
				session.execute(
					f"INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES "
					f'("pytest-prod-{idx}", "1.0", "1", "{get_depotserver_id()}", "LocalbootProduct");'
				)

			session.execute(
				"INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) VALUES  "
				'("pytest-prod-1", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 1 version 2", 60),'
				'("pytest-prod-4", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 4 version 2", 60);'
			)

			# Host
			for idx in range(5):
				session.execute(
					f"INSERT INTO HOST (hostId, `type`, created, lastSeen, hardwareAddress, `description`, notes, inventoryNumber) "
					f'VALUES ("pytest-client-{idx}.uib.local", "OpsiClient", "{now}", "{now}", "af:fe:af:fe:af:f{idx}", '
					f'"description client{idx}", "notes client{idx}", "{idx}");'
				)
			session.execute(
				"INSERT INTO HOST (hostId, type, created, lastSeen) VALUES "
				f'("pytest-lost-client.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}"),'
				f'("pytest-lost-client-fp.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}"),'
				f'("pytest-lost-client-fp2.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}");'
			)

			create_depot_jsonrpc(test_client, config.internal_url, "pytest-test-depot.opsi.test")
			create_depot_jsonrpc(test_client, config.internal_url, "pytest-test-depot2.opsi.test")

			# Product on client
			session.execute(
				"INSERT INTO PRODUCT_ON_CLIENT "
				"(productId, clientId, productType, installationStatus, actionRequest, actionResult, "
				" productVersion, packageVersion, modificationTime) VALUES "
				f'("pytest-prod-1", "pytest-client-1.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}"),'
				f'("pytest-prod-2", "pytest-client-2.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}"),'
				f'("pytest-prod-3", "pytest-client-3.uib.local", "LocalbootProduct", "installed", "none", "none", "1.0", 1, "{now}"),'
				f'("pytest-prod-2", "pytest-lost-client-fp.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}"),'
				f'("pytest-prod-2", "pytest-lost-client-fp2.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}"),'
				f'("pytest-prod-1", "pytest-lost-client-fp2.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}"),'
				f'("pytest-prod-4", "pytest-client-0.uib.local", "LocalbootProduct", "not_installed", "none", "none", "1.0", 1, "{now}"),'
				f'("pytest-prod-4", "pytest-client-1.uib.local", "LocalbootProduct", "not_installed", "none", "none", "1.0", 1, "{now}"),'
				f'("pytest-prod-4", "pytest-client-4.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}");'
			)

			# Product on depot
			session.execute(
				"INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES "
				'("pytest-prod-1", "1.0", "1", "pytest-test-depot.opsi.test", "LocalbootProduct"),'
				'("pytest-prod-2", "1.0", "1", "pytest-test-depot.opsi.test", "LocalbootProduct"),'
				'("pytest-prod-1", "2.0", "1", "pytest-test-depot2.opsi.test", "LocalbootProduct"),'
				'("pytest-prod-2", "1.0", "1", "pytest-test-depot2.opsi.test", "LocalbootProduct"),'
				'("pytest-prod-3", "1.0", "1", "pytest-test-depot.opsi.test", "LocalbootProduct"),'
				'("pytest-prod-4", "1.0", "1", "pytest-test-depot.opsi.test", "LocalbootProduct"),'
				'("pytest-prod-3", "1.0", "1", "pytest-test-depot2.opsi.test", "LocalbootProduct"),'
				'("pytest-prod-4", "2.0", "1", "pytest-test-depot2.opsi.test", "LocalbootProduct");'
			)

			# Product Group
			session.execute(
				'INSERT INTO `GROUP` (type, groupId) VALUES ("ProductGroup", "pytest-group-1"), ("ProductGroup", "pytest-group-2");'
			)

			session.execute(
				"INSERT INTO OBJECT_TO_GROUP (groupType, groupId, objectId) VALUES "
				'("ProductGroup", "pytest-group-1", "pytest-prod-0"),'
				'("ProductGroup", "pytest-group-1", "pytest-prod-1"),'
				'("ProductGroup", "pytest-group-1", "pytest-prod-2"),'
				'("ProductGroup", "pytest-group-2", "pytest-prod-3"),'
				'("ProductGroup", "pytest-group-2", "pytest-prod-4");'
			)

			res = session.execute('SELECT configId from CONFIG WHERE configId="clientconfig.depot.id";')
			if res == 0:
				session.execute(
					"INSERT INTO CONFIG (configId, `type`, description, multiValue, editable) VALUES "
					'("clientconfig.depot.id", "UnicodeConfig", "ID of the opsi depot to use", 0, 1);'
				)

				session.execute(
					"INSERT INTO CONFIG_VALUE (configId, value, isDefault) VALUES "
					f'("clientconfig.depot.id", "{get_depotserver_id()}", 1);'
				)

			# Clients to Depots
			session.execute(
				"INSERT INTO CONFIG_STATE (configId, objectId, CONFIG_STATE.values) VALUES "
				'("clientconfig.depot.id", "pytest-client-1.uib.local", \'["pytest-test-depot.opsi.test"]\'),'
				'("clientconfig.depot.id", "pytest-client-2.uib.local", \'["pytest-test-depot.opsi.test"]\'),'
				'("clientconfig.depot.id", "pytest-client-3.uib.local",	\'["pytest-test-depot2.opsi.test"]\'),'
				'("clientconfig.depot.id", "pytest-client-4.uib.local", \'["pytest-test-depot2.opsi.test"]\');'
			)

	yield

	delete_mysql_data()


@pytest.mark.parametrize("info, opsiresource, thresholds, expected_result", test_data)
def test_check_disk_usage(
	backend: UnprotectedBackend,  # noqa: F811
	info: dict[str, Any],
	opsiresource: Any,
	thresholds: Any,
	expected_result: Any,
) -> None:
	def get_disk_usage(path: str) -> DiskUsage:
		return DiskUsage(**info)

	with mock.patch("opsiconfd.application.monitoring.check_opsi_disk_usage.get_disk_usage", get_disk_usage):
		result = check_opsi_disk_usage(thresholds=thresholds, opsiresource=opsiresource)

	assert expected_result == json.loads(result.body)


@pytest.mark.parametrize("return_value", [(None), ({}), ([])])
def test_check_disk_usage_no_result(
	backend: UnprotectedBackend,  # noqa: F811
	return_value: Any,
) -> None:
	def get_disk_usage(path: str) -> DiskUsage:
		return return_value

	with mock.patch("opsiconfd.application.monitoring.check_opsi_disk_usage.get_disk_usage", get_disk_usage):
		result = check_opsi_disk_usage(opsiresource=["not-a-resource"])

	assert json.loads(result.body) == {"message": ("UNKNOWN: No disk usage results, nothing to check."), "state": 3}


def test_check_locked_products(backend: UnprotectedBackend) -> None:  # noqa: F811
	result = check_locked_products(backend, depot_ids=["pytest-test-depot.opsi.test"])
	assert json.loads(result.body) == {"message": "OK: No products locked on depots: pytest-test-depot.opsi.test", "state": 0}

	result = check_locked_products(backend, depot_ids=[])
	assert json.loads(result.body) == {
		"message": (
			f"OK: No products locked on depots: {get_depotserver_id()}," "pytest-test-depot.opsi.test,pytest-test-depot2.opsi.test"
		),
		"state": 0,
	}
	mysql = MySQLConnection()
	with mysql.connection():
		with mysql.session() as session:
			session.execute(
				(
					"REPLACE INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType, locked) VALUES "
					'("pytest-prod-3", "1.0", "1", "pytest-test-depot.opsi.test", "LocalbootProduct", true),'
					'("pytest-prod-2", "1.0", "1", "pytest-test-depot.opsi.test", "LocalbootProduct", true);'
				)
			)

	time.sleep(2)

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.opsi.test"])
	assert json.loads(result.body) == {
		"message": (
			"WARNING: 2 products are in locked state.\n"
			"Product pytest-prod-2 locked on depot pytest-test-depot.opsi.test\n"
			"Product pytest-prod-3 locked on depot pytest-test-depot.opsi.test"
		),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.opsi.test", get_depotserver_id()])
	assert json.loads(result.body) == {
		"message": (
			"WARNING: 2 products are in locked state.\n"
			"Product pytest-prod-2 locked on depot pytest-test-depot.opsi.test\n"
			"Product pytest-prod-3 locked on depot pytest-test-depot.opsi.test"
		),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.opsi.test", get_depotserver_id()], product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		"message": ("WARNING: 1 products are in locked state.\n" "Product pytest-prod-2 locked on depot pytest-test-depot.opsi.test"),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=[], product_ids=None)
	assert json.loads(result.body) == {
		"message": (
			"WARNING: 2 products are in locked state.\n"
			"Product pytest-prod-2 locked on depot pytest-test-depot.opsi.test\n"
			"Product pytest-prod-3 locked on depot pytest-test-depot.opsi.test"
		),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=None, product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		"message": ("WARNING: 1 products are in locked state.\n" "Product pytest-prod-2 locked on depot pytest-test-depot.opsi.test"),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=["all"], product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		"message": ("WARNING: 1 products are in locked state.\n" "Product pytest-prod-2 locked on depot pytest-test-depot.opsi.test"),
		"state": 1,
	}


@pytest.mark.parametrize(
	"product_id, thresholds, expected_result",
	[
		(
			"pytest-prod-1",
			{},
			{
				"message": (
					"WARNING: 2 ProductStates for product: 'pytest-prod-1' found; "
					"checking for Version: '1.0' and Package: '1'; ActionRequest set on 2 clients"
				),
				"state": 1,
			},
		),
		(
			"pytest-prod-2",
			{},
			{
				"message": (
					"CRITICAL: 3 ProductStates for product: 'pytest-prod-2' found; "
					"checking for Version: '1.0' and Package: '1'; Problems found on 3 clients"
				),
				"state": 2,
			},
		),
		(
			"pytest-prod-1",
			{"warning": "50", "critical": "70"},
			{
				"message": (
					"WARNING: 2 ProductStates for product: 'pytest-prod-1' found; "
					"checking for Version: '1.0' and Package: '1'; ActionRequest set on 2 clients"
				),
				"state": 1,
			},
		),
		(
			"pytest-prod-4",
			{"warning": "50", "critical": "60"},
			{
				"message": ("OK: 3 ProductStates for product: 'pytest-prod-4' found; checking for Version: '1.0' and Package: '1'"),
				"state": 0,
			},
		),
		(
			"pytest-prod-4",
			{"warning": "20", "critical": "30"},
			{
				"message": (
					"WARNING: 3 ProductStates for product: 'pytest-prod-4' found; "
					"checking for Version: '1.0' and Package: '1'; ActionRequest set on 1 clients"
				),
				"state": 1,
			},
		),
		(
			"pytest-prod-4",
			{"warning": "5", "critical": "10"},
			{
				"message": (
					"WARNING: 3 ProductStates for product: 'pytest-prod-4' found; "
					"checking for Version: '1.0' and Package: '1'; ActionRequest set on 1 clients"
				),
				"state": 1,
			},
		),
		(
			"pytest-prod-3",
			{},
			{
				"message": ("OK: 1 ProductStates for product: 'pytest-prod-3' found; " "checking for Version: '1.0' and Package: '1'"),
				"state": 0,
			},
		),
	],
)
def test_check_short_product_status(
	backend: UnprotectedBackend,  # noqa: F811
	product_id: str,
	thresholds: dict,
	expected_result: Any,
) -> None:
	result = check_short_product_status(backend, product_id=product_id, thresholds=thresholds)
	assert json.loads(result.body) == expected_result


@pytest.mark.parametrize(
	"params, reachable, command_result, expected_result",
	[
		(
			{
				"host_id": "pytest-client-4.uib.local",
				"command": "echo 'this is a test'",
			},
			True,
			{"result": ["this is a test"], "error": None},
			{"message": "OK: this is a test", "state": 0},
		),
		(
			{
				"host_id": "pytest-client-4.uib.local",
				"command": "blabla",
			},
			True,
			{
				"result": None,
				"error": {
					"class": "RuntimeError",
					"message": "RuntimeError(\"Command 'blabla' failed (127):\\n/bin/sh: 1: lsblka: not found\\n\")",
				},
			},
			{"message": "UNKNOWN: Unable to parse Errorcode from plugin", "state": 3},
		),
		(
			{
				"host_id": "pytest-client-4.uib.local",
				"command": "blabla",
			},
			False,
			{},
			{"message": "UNKNOWN: Can't check host 'pytest-client-4.uib.local' is not reachable.", "state": 3},
		),
	],
)
def test_check_client_plugin(
	backend: UnprotectedBackend,  # noqa: F811
	params: dict,
	reachable: bool,
	command_result: dict,
	expected_result: dict,
) -> None:
	def host_control_safe_reachable(hostIds: list[str]) -> dict:
		return {hostIds[0]: reachable}

	def host_control_safe_execute(
		command: str,
		hostIds: list[str],
		waitForEnding: bool,
		captureStderr: bool,
		encoding: str,
		timeout: float,
	) -> dict:
		return {hostIds[0]: command_result}

	mock_backend = mock.Mock(backend)
	mock_backend.hostControlSafe_reachable = host_control_safe_reachable
	mock_backend.hostControlSafe_execute = host_control_safe_execute

	result = check_plugin_on_client(
		mock_backend,
		host_id=str(params.get("host_id")),
		command=str(params.get("command")),
		timeout=int(params.get("timeout", 0)),
	)

	assert json.loads(result.body) == expected_result


def test_monitoring_user_permissions(backend: UnprotectedBackend, test_client: OpsiconfdTestClient) -> None:  # noqa: F811  # noqa: F811
	backend.user_setCredentials("monitoring", "monitoring123")

	res = test_client.post("/rpc", auth=("monitoring", "monitoring123"), json={"method": "host_getObjects", "params": []})
	print(res.json())
	print(res.status_code)
	result_json = res.json()
	assert res.status_code == 200
	assert result_json.get("error")
	assert result_json["error"].get("class") == "OpsiServicePermissionError"
	assert result_json["error"].get("message") == "Opsi service permission error: No permission for method 'host_getObjects'"

	with get_config({"multi-factor-auth": "totp_mandatory"}):
		res = test_client.post("/session/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
		print("admin login: ", res.json())
		assert res.status_code == 401
		assert "MFA OTP configuration error" in res.json()["message"]

		res = test_client.post("/session/login", json={"username": "monitoring", "password": "monitoring123"})
		print("monitoring login: ", res.json())
		assert res.status_code == 200
		assert res.json().get("is_admin") is False

		res = test_client.post("/monitoring", auth=("monitoring", "monitoring123"), json={})
		print(res.json())
		print(res.status_code)
		assert res.status_code == 200
		assert res.json()["state"] == 3
		assert res.json()["message"] == "No matching task found."

	backend.user_delete("monitoring")
