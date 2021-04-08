# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

'''
Tests for the opsiconfd monitoring module
'''

import errno
import os
import socket
import time
import tempfile
import unittest.mock as mock
import json
import pytest

import MySQLdb

from opsiconfd.application.monitoring.check_opsi_disk_usage import check_opsi_disk_usage
from opsiconfd.application.monitoring.check_locked_products import check_locked_products
from opsiconfd.application.monitoring.check_short_product_status import check_short_product_status
from opsiconfd.backend import get_backend
from .utils import clean_redis, config, create_check_data, TEST_USER, TEST_PW, HOSTNAME, LOCAL_IP, DAYS # pylint: disable=unused-import

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
		{"state": 0, "message": "OK: DiskUsage from ressource '/workbench' is ok. (available:  20.00GB)."}
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
		{"state": 2, "message": "CRITICAL: DiskUsage from ressource: '/workbench' is critical (available: 1.00GB)."}
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
		{"state": 1, "message": "WARNING: DiskUsage warning from ressource: '/workbench' (available: 5.00GB)."}
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
		{"state": 1, "message": "WARNING: DiskUsage warning from ressource: '/workbench' (available: 20.00GB)."}
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
		{"state": 2, "message": "CRITICAL: DiskUsage from ressource: '/workbench' is critical (available: 20.00GB)."}
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
		{"state": 2, "message": ("CRITICAL: DiskUsage from ressource: '/depot' is critical (available: 20.00GB). "
		"DiskUsage from ressource: '/workbench' is critical (available: 20.00GB).")}
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
		{"state": 2, "message": ("CRITICAL: DiskUsage from ressource: '/depot' is critical (available: 20.00%). "
		"DiskUsage from ressource: '/workbench' is critical (available: 20.00%).")}
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
		{"state": 0, "message": "OK: DiskUsage from ressource: '/depot' is ok. (available: 20.00%)."}
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
			"message": ("OK: DiskUsage from ressource: '/depot' is ok. (available: 20.00%). "
				"DiskUsage from ressource: '/repository' is ok. (available: 20.00%). "
				"DiskUsage from ressource: '/workbench' is ok. (available: 20.00%)."
			)
		}
	)

]

@pytest.mark.parametrize("info, opsiresource, thresholds, expected_result", test_data)
def test_check_disk_usage(info, opsiresource, thresholds, expected_result): # pylint: disable=too-many-arguments

	def get_info(path):
		print(path)
		return info

	backend = get_backend()

	with mock.patch('opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage', get_info):
		result = check_opsi_disk_usage(backend, thresholds=thresholds, opsiresource=opsiresource)

	assert json.loads(result.body) == expected_result


def test_check_disk_usage_error(): # pylint: disable=too-many-arguments

	def get_info(path):
		raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)

	backend = get_backend()

	with mock.patch('opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage', get_info):
		result = check_opsi_disk_usage(backend, thresholds={}, opsiresource="workbench")

	assert json.loads(result.body) == {
		'message': ('UNKNOWN: ["Not able to check DiskUsage. Error: \'[Errno 2] '
			'No such file or directory: \'/var/lib/opsi/workbench\'\'"]'),
		'state': 3
		}

test_data = [
	(None),
	({}),
	([])

]

@pytest.mark.parametrize("return_value", test_data)
def test_check_disk_usage_no_result(return_value): # pylint: disable=too-many-arguments

	def get_info(path):
		return return_value

	backend = get_backend()

	with mock.patch('opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage', get_info):
		result = check_opsi_disk_usage(backend, opsiresource="not-a-resource")

	assert json.loads(result.body) == {
		'message': ('UNKNOWN: No results get. Nothing to check.'),
		'state': 3
		}


def test_check_locked_products():

	backend = get_backend()

	result = check_locked_products(backend, depot_ids=["pytest-test-depot.uib.gmbh"])
	assert json.loads(result.body) == {'message': 'OK: No products locked on depots: pytest-test-depot.uib.gmbh', 'state': 0}

	result = check_locked_products(backend, depot_ids=[])
	assert json.loads(result.body) == {
		'message': (f'OK: No products locked on depots: {socket.getfqdn()},'
			'pytest-test-depot.uib.gmbh,pytest-test-depot2.uib.gmbh'),
		'state': 0
	}


	mysql_host = os.environ.get("MYSQL_HOST")
	if not mysql_host:
		mysql_host = "127.0.0.1"

	db=MySQLdb.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi") # pylint: disable=invalid-name, c-extension-no-member
	db.autocommit(True)
	cursor = db.cursor()
	cursor.execute((
			'REPLACE INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType, locked) '
			'VALUES ("pytest-prod-3", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct", true);'
			'REPLACE INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType, locked) '
			'VALUES ("pytest-prod-2", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct", true);'
		)
	)
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
def test_check_short_product_status(product_id, thresholds, expected_result): # pylint: disable=too-many-arguments

	backend = get_backend()
	result = check_short_product_status(backend, product_id=product_id, thresholds=thresholds)
	assert json.loads(result.body) == expected_result
