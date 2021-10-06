# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

'''
Tests for the opsiconfd monitoring module
'''

import socket
import time
from unittest import mock
import json
import pytest

from opsiconfd.application.monitoring.check_opsi_disk_usage import check_opsi_disk_usage
from opsiconfd.application.monitoring.check_locked_products import check_locked_products
from opsiconfd.application.monitoring.check_short_product_status import check_short_product_status
from opsiconfd.application.monitoring.check_plugin_on_client import check_plugin_on_client

from .utils import ( # pylint: disable=unused-import
	config, clean_redis, create_check_data, database_connection, backend
)

test_data = [
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"workbench",
		{},
		{"state": 0, "message": "OK: DiskUsage from ressource 'workbench' is ok. (available:  20.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 1073741824,
			'used': 106300440576,
			'usage': 0.99
		},
		"workbench",
		{},
		{"state": 2, "message": "CRITICAL: DiskUsage from ressource: 'workbench' is critical (available: 1.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 5368709120,
			'used': 102005473280,
			'usage': 0.95
		},
		"workbench",
		{},
		{"state": 1, "message": "WARNING: DiskUsage warning from ressource: 'workbench' (available: 5.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"workbench",
		{"warning": "30G", "critical": "10G"},
		{"state": 1, "message": "WARNING: DiskUsage warning from ressource: 'workbench' (available: 20.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"workbench",
		{"warning": "30G", "critical": "20G"},
		{"state": 2, "message": "CRITICAL: DiskUsage from ressource: 'workbench' is critical (available: 20.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		["depot", "workbench"],
		{"warning": "30G", "critical": "20G"},
		{"state": 2, "message": ("CRITICAL: DiskUsage from ressource: 'depot' is critical (available: 20.00GB). "
		"DiskUsage from ressource: 'workbench' is critical (available: 20.00GB).")}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		["depot", "workbench"],
		{"warning": "30%", "critical": "20%"},
		{"state": 2, "message": ("CRITICAL: DiskUsage from ressource: 'depot' is critical (available: 20.00%). "
		"DiskUsage from ressource: 'workbench' is critical (available: 20.00%).")}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"depot",
		{"warning": "10%", "critical": "5%"},
		{"state": 0, "message": "OK: DiskUsage from ressource: 'depot' is ok. (available: 20.00%)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"not-a-resource",
		{"warning": "10%", "critical": "5%"},
		{"state": 3, "message": "UNKNOWN: No results get. Nothing to check."}
	)
	,
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		None,
		{"warning": "10%", "critical": "5%"},
		{
			"state": 0,
			"message": ("OK: DiskUsage from ressource: 'depot' is ok. (available: 20.00%). "
				"DiskUsage from ressource: 'repository' is ok. (available: 20.00%). "
				"DiskUsage from ressource: 'workbench' is ok. (available: 20.00%)."
			)
		}
	)

]

@pytest.mark.parametrize("info, opsiresource, thresholds, expected_result", test_data)
def test_check_disk_usage(backend, info, opsiresource, thresholds, expected_result):  # pylint: disable=too-many-arguments,redefined-outer-name

	def get_info(path):  # pylint: disable=unused-argument
		return info

	with mock.patch('opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage', get_info):
		result = check_opsi_disk_usage(backend, thresholds=thresholds, opsiresource=opsiresource)

	assert expected_result == json.loads(result.body)


test_data = [
	(None),
	({}),
	([])

]
@pytest.mark.parametrize("return_value", test_data)
def test_check_disk_usage_no_result(backend, return_value): # pylint: disable=too-many-arguments,redefined-outer-name

	def get_info(path):
		print(path)
		return return_value

	with mock.patch('opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage', get_info):
		result = check_opsi_disk_usage(backend, opsiresource="not-a-resource")

	assert json.loads(result.body) == {
		'message': ('UNKNOWN: No results get. Nothing to check.'),
		'state': 3
		}


def test_check_locked_products(backend, database_connection):  # pylint: disable=redefined-outer-name

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh"])
	assert json.loads(result.body) == {'message': 'OK: No products locked on depots: pytest-test-depot.uib.gmbh', 'state': 0}

	result = check_locked_products(backend, depot_ids=[])
	assert json.loads(result.body) == {
		'message': (
			f'OK: No products locked on depots: {socket.getfqdn()},'
			'pytest-test-depot.uib.gmbh,pytest-test-depot2.uib.gmbh'
		),
		'state': 0
	}

	cursor = database_connection.cursor()
	cursor.execute((
			'REPLACE INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType, locked) VALUES '
			'("pytest-prod-3", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct", true),'
			'("pytest-prod-2", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct", true);'
		)
	)
	database_connection.commit()
	cursor.close()

	time.sleep(2)

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh"])
	assert json.loads(result.body) == {
		'message': ('WARNING: 2 products are in locked state.\n'
			'Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh\n'
			'Product pytest-prod-3 locked on depot pytest-test-depot.uib.gmbh'),
		'state': 1
	}

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh", socket.getfqdn()])
	assert json.loads(result.body) == {
		'message': ('WARNING: 2 products are in locked state.\n'
			'Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh\n'
			'Product pytest-prod-3 locked on depot pytest-test-depot.uib.gmbh'),
		'state': 1
	}

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh", socket.getfqdn()], product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		'message': ('WARNING: 1 products are in locked state.\n'
			'Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh'),
		'state': 1
	}

	result = check_locked_products(backend, depot_ids=[], product_ids=None)
	assert json.loads(result.body) == {
		'message': ('WARNING: 2 products are in locked state.\n'
			'Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh\n'
			'Product pytest-prod-3 locked on depot pytest-test-depot.uib.gmbh'),
		'state': 1
	}

	result = check_locked_products(backend, depot_ids=None, product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		'message': ('WARNING: 1 products are in locked state.\n'
			'Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh'),
		'state': 1
	}

	result = check_locked_products(backend, depot_ids="all", product_ids=["pytest-prod-2"])
	assert json.loads(result.body) == {
		'message': ('WARNING: 1 products are in locked state.\n'
			'Product pytest-prod-2 locked on depot pytest-test-depot.uib.gmbh'),
		'state': 1
	}

test_data = [
	(
		"pytest-prod-1",
		{},
		{
			'message': ("WARNING: 2 ProductStates for product: 'pytest-prod-1' found; "
				"checking for Version: '1.0' and Package: '1'; ActionRequest set on 2 clients"),
			'state': 1
		}
	),
	(
		"pytest-prod-2",
		{},
		{
			'message': ("CRITICAL: 3 ProductStates for product: 'pytest-prod-2' found; "
				"checking for Version: '1.0' and Package: '1'; Problems found on 3 clients"),
			'state': 2
		}
	),
	(
		"pytest-prod-1",
		{"warning": "50", "critical": "70"},
		{
			'message': ("WARNING: 2 ProductStates for product: 'pytest-prod-1' found; "
				"checking for Version: '1.0' and Package: '1'; ActionRequest set on 2 clients"),
			'state': 1
		}
	),
	(
		"pytest-prod-4",
		{"warning": "50", "critical": "60"},
		{
			'message': ("OK: 3 ProductStates for product: 'pytest-prod-4' found; checking for Version: '1.0' and Package: '1'"),
			'state': 0
		}
	),
	(
		"pytest-prod-4",
		{"warning": "20", "critical": "30"},
		{
			'message': ("WARNING: 3 ProductStates for product: 'pytest-prod-4' found; "
				"checking for Version: '1.0' and Package: '1'; ActionRequest set on 1 clients"),
			'state': 1
		}
	),
	(
		"pytest-prod-4",
		{"warning": "5", "critical": "10"},
		{
			'message': ("WARNING: 3 ProductStates for product: 'pytest-prod-4' found; "
				"checking for Version: '1.0' and Package: '1'; ActionRequest set on 1 clients"),
			'state': 1
		}
	),
	(
		"pytest-prod-3",
		{},
		{
			'message':  ("OK: 1 ProductStates for product: 'pytest-prod-3' found; "
				"checking for Version: '1.0' and Package: '1'"),
			'state': 0
		}
	)
]

@pytest.mark.parametrize("product_id, thresholds, expected_result", test_data)
def test_check_short_product_status(backend, product_id, thresholds, expected_result): # pylint: disable=too-many-arguments,redefined-outer-name
	result = check_short_product_status(backend, product_id=product_id, thresholds=thresholds)
	assert json.loads(result.body) == expected_result

test_data = [
	(
		{
			"host_id": "pytest-client-4.uib.local",
			"command": "echo 'this is a test'",
		},
		True,
		{
				"result": ["this is a test"],
				"error": None
		},
		{'message': 'OK: this is a test', 'state': 0}
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
				"message": "RuntimeError(\"Command 'blabla' failed (127):\\n/bin/sh: 1: lsblka: not found\\n\")"}
		},
		{'message': 'UNKNOWN: Unable to parse Errorcode from plugin', 'state': 3}
	),
	(
		{
			"host_id": "pytest-client-4.uib.local",
			"command": "blabla",
		},
		False,
		{},
		{"message": "UNKNOWN: Can't check host 'pytest-client-4.uib.local' is not reachable.", "state": 3}
	)
]
@pytest.mark.parametrize("params, reachable, command_result, expected_result", test_data)
def test_check_client_plugin(backend, params, reachable, command_result, expected_result): # pylint: disable=too-many-arguments,redefined-outer-name

	def host_control_safe_reachable(hostIds): # pylint: disable=invalid-name
		return {hostIds[0]: reachable}

	def host_control_safe_execute(command, hostIds, waitForEnding, captureStderr, encoding, timeout): # pylint: disable=unused-argument, invalid-name, too-many-arguments
		return {
			hostIds[0]: command_result
		}

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
