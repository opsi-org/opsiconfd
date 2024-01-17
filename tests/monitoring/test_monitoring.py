# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
Tests for the opsiconfd monitoring module
"""

import json
import socket
import time
from datetime import datetime, timedelta
from unittest import mock

import pytest

from OPSI.Backend.MySQL import retry_on_deadlock

from opsiconfd.application.monitoring.check_locked_products import check_locked_products
from opsiconfd.application.monitoring.check_opsi_disk_usage import check_opsi_disk_usage
from opsiconfd.application.monitoring.check_plugin_on_client import (
	check_plugin_on_client,
)
from opsiconfd.application.monitoring.check_short_product_status import (
	check_short_product_status,
)

from tests.utils import (  # pylint: disable=unused-import
	backend,
	clean_redis,
	config,
	create_depot_jsonrpc,
	database_connection,
	test_client,
)

MONITORING_CHECK_DAYS = 31

test_data = [
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
		{"state": 3, "message": "UNKNOWN: No results get. Nothing to check."},
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
]


@pytest.fixture(autouse=True)
def create_check_data(test_client, config, database_connection):  # pylint: disable=redefined-outer-name
	mysql = database_connection
	mysql.autocommit(True)
	now = datetime.now()

	@retry_on_deadlock
	def execute(
		cursor, *args, **kwargs):
		return cursor.execute(*args, **kwargs)

	cursor = mysql.cursor()

	execute(
		cursor,
		(
			"DELETE FROM PRODUCT_ON_DEPOT;"
			"DELETE FROM PRODUCT_ON_CLIENT;"
			"DELETE FROM PRODUCT_PROPERTY_VALUE;"
			"DELETE FROM PRODUCT_PROPERTY;"
			"DELETE FROM PRODUCT_DEPENDENCY;"
			"DELETE FROM OBJECT_TO_GROUP;"
			"DELETE FROM PRODUCT;"
			'DELETE FROM HOST WHERE type != "OpsiConfigserver";'
			"DELETE FROM `GROUP`;"
			'DELETE FROM CONFIG_STATE WHERE objectId like "pytest%";'
		)
	)

	# Product
	for i in range(5):
		execute(
			cursor,
			f"INSERT INTO HOST (hostId, `type`, created, lastSeen, hardwareAddress, `description`, notes, inventoryNumber) "
			f'VALUES ("pytest-client-{i}.uib.local", "OpsiClient", "{now}", "{now}", "af:fe:af:fe:af:f{i}", '
			f'"description client{i}", "notes client{i}", "{i}");'
		)
		execute(
			cursor,
			"INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority, setupScript, uninstallScript) VALUES "
			f'("pytest-prod-{i}", "1.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT {i}", 60+{i}, "setup.opsiscript", "uninstall.opsiscript");'
		)
		execute(
			cursor,
			f"INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES "
			f'("pytest-prod-{i}", "1.0", "1", "{socket.getfqdn()}", "LocalbootProduct");'
		)

	execute(
		cursor,
		"INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) VALUES  "
		'("pytest-prod-1", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 1 version 2", 60),'
		'("pytest-prod-4", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 4 version 2", 60);'
	)

	# Host
	execute(
		cursor,
		"INSERT INTO HOST (hostId, type, created, lastSeen) VALUES "
		f'("pytest-lost-client.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}"),'
		f'("pytest-lost-client-fp.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}"),'
		f'("pytest-lost-client-fp2.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}");'
	)

	create_depot_jsonrpc(test_client, config.internal_url, "pytest-test-depot.uib.gmbh")
	create_depot_jsonrpc(test_client, config.internal_url, "pytest-test-depot2.uib.gmbh")

	# Product on client
	execute(
		cursor,
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
	execute(
		cursor,
		"INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES "
		'("pytest-prod-1", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-2", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-1", "2.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-2", "1.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-3", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-4", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-3", "1.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-4", "2.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct");'
	)

	# Product Group
	execute(
		cursor,
		'INSERT INTO `GROUP` (type, groupId) VALUES ("ProductGroup", "pytest-group-1"), ("ProductGroup", "pytest-group-2");'
	)
	execute(
		cursor,
		"INSERT INTO OBJECT_TO_GROUP (groupType, groupId, objectId) VALUES "
		'("ProductGroup", "pytest-group-1", "pytest-prod-0"),'
		'("ProductGroup", "pytest-group-1", "pytest-prod-1"),'
		'("ProductGroup", "pytest-group-1", "pytest-prod-2"),'
		'("ProductGroup", "pytest-group-2", "pytest-prod-3"),'
		'("ProductGroup", "pytest-group-2", "pytest-prod-4");'
	)

	# Clients to Depots
	execute(
		cursor,
		"INSERT INTO CONFIG_STATE (configId, objectId, CONFIG_STATE.values) VALUES "
		'("clientconfig.depot.id", "pytest-client-1.uib.local", \'["pytest-test-depot.uib.gmbh"]\'),'
		'("clientconfig.depot.id", "pytest-client-2.uib.local", \'["pytest-test-depot.uib.gmbh"]\'),'
		'("clientconfig.depot.id", "pytest-client-3.uib.local",	\'["pytest-test-depot2.uib.gmbh"]\'),'
		'("clientconfig.depot.id", "pytest-client-4.uib.local", \'["pytest-test-depot2.uib.gmbh"]\');'
	)

	cursor.close()

	yield

	cursor = mysql.cursor()
	# execute(
	# cursor,
	# 	(
	# 		'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "pytest%";'
	# 		'DELETE FROM PRODUCT_ON_CLIENT WHERE productId like "pytest%";'
	# 		'DELETE FROM OBJECT_TO_GROUP WHERE groupId like "pytest%";'
	# 		'DELETE FROM PRODUCT WHERE productId like "pytest%";'
	# 		'DELETE FROM HOST WHERE hostId like "pytest%";'
	# 		'DELETE FROM opsi.GROUP WHERE groupId like "pytest%";'
	# 		'DELETE FROM CONFIG_STATE WHERE objectId like "pytest%";'
	# 	)
	# )
	execute(
		cursor,
		"DELETE FROM PRODUCT_ON_DEPOT;"
		"DELETE FROM PRODUCT_ON_CLIENT;"
		"DELETE FROM PRODUCT_PROPERTY_VALUE;"
		"DELETE FROM PRODUCT_PROPERTY;"
		"DELETE FROM PRODUCT_DEPENDENCY;"
		"DELETE FROM OBJECT_TO_GROUP;"
		"DELETE FROM PRODUCT;"
		'DELETE FROM HOST WHERE type!="OpsiConfigserver";'
		"DELETE FROM `GROUP`;"
		"DELETE FROM CONFIG_STATE;"
	)


@pytest.mark.parametrize("info, opsiresource, thresholds, expected_result", test_data)
def test_check_disk_usage(
	backend, info, opsiresource, thresholds, expected_result
):  # pylint: disable=too-many-arguments,redefined-outer-name
	def get_info(path):  # pylint: disable=unused-argument
		return info

	with mock.patch("opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage", get_info):
		result = check_opsi_disk_usage(backend, thresholds=thresholds, opsiresource=opsiresource)

	assert expected_result == json.loads(result.body)


@pytest.mark.parametrize("return_value", [(None), ({}), ([])])
def test_check_disk_usage_no_result(backend, return_value):  # pylint: disable=too-many-arguments,redefined-outer-name
	def get_info(path):
		print(path)
		return return_value

	with mock.patch("opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage", get_info):
		result = check_opsi_disk_usage(backend, opsiresource="not-a-resource")

	assert json.loads(result.body) == {"message": ("UNKNOWN: No results get. Nothing to check."), "state": 3}


def test_check_locked_products(backend, database_connection):  # pylint: disable=redefined-outer-name

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh"])
	assert json.loads(result.body) == {"message": "OK: No products locked on depots: pytest-test-depot.uib.gmbh", "state": 0}

	result = check_locked_products(backend, depot_ids=[])
	assert json.loads(result.body) == {
		"message": (f"OK: No products locked on depots: {socket.getfqdn()}," "pytest-test-depot.uib.gmbh,pytest-test-depot2.uib.gmbh"),
		"state": 0,
	}

	cursor = database_connection.cursor()
	cursor.execute(
		(
			"REPLACE INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType, locked) VALUES "
			'("pytest-prod-3", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct", true),'
			'("pytest-prod-2", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct", true);'
		)
	)
	database_connection.commit()
	cursor.close()

	time.sleep(2)

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh"])
	assert json.loads(result.body) == {
		"message": (
			"WARNING: 2 products are in locked state.\n"
			"Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh\n"
			"Product pytest-prod-3 locked on depot pytest-test-depot.uib.gmbh"
		),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh", socket.getfqdn()])
	assert json.loads(result.body) == {
		"message": (
			"WARNING: 2 products are in locked state.\n"
			"Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh\n"
			"Product pytest-prod-3 locked on depot pytest-test-depot.uib.gmbh"
		),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh", socket.getfqdn()], product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		"message": ("WARNING: 1 products are in locked state.\n" "Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh"),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=[], product_ids=None)
	assert json.loads(result.body) == {
		"message": (
			"WARNING: 2 products are in locked state.\n"
			"Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh\n"
			"Product pytest-prod-3 locked on depot pytest-test-depot.uib.gmbh"
		),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids=None, product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		"message": ("WARNING: 1 products are in locked state.\n" "Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh"),
		"state": 1,
	}

	result = check_locked_products(backend, depot_ids="all", product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		"message": ("WARNING: 1 products are in locked state.\n" "Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh"),
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
	backend, product_id, thresholds, expected_result
):  # pylint: disable=too-many-arguments,redefined-outer-name
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
	backend, params, reachable, command_result, expected_result
):  # pylint: disable=too-many-arguments,redefined-outer-name
	def host_control_safe_reachable(hostIds):  # pylint: disable=invalid-name
		return {hostIds[0]: reachable}

	def host_control_safe_execute(
		command, hostIds, waitForEnding, captureStderr, encoding, timeout
	):  # pylint: disable=unused-argument, invalid-name, too-many-arguments
		return {hostIds[0]: command_result}

	mock_backend = mock.Mock(backend)
	mock_backend.hostControlSafe_reachable = host_control_safe_reachable
	mock_backend.hostControlSafe_execute = host_control_safe_execute

	result = check_plugin_on_client(
		mock_backend,
		host_id=params.get("host_id"),
		command=params.get("command"),
		timeout=params.get("timeout"),
	)

	assert json.loads(result.body) == expected_result
