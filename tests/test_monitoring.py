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
import unittest.mock as mock
import json
import pytest
from fastapi.responses import JSONResponse

from opsiconfd.application.monitoring.check_opsi_disk_usage import check_opsi_disk_usage

test_data = [
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"/var/opsi",
		{},
		{"state": 0, "message": "OK: DiskUsage from ressource '/var/opsi' is ok. (available:  20.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 1073741824,
			'used': 106300440576,
			'usage': 0.99
		},
		"/var/opsi",
		{},
		{"state": 2, "message": "CRITICAL: DiskUsage from ressource: '/var/opsi' is critical (available: 1.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 5368709120,
			'used': 102005473280,
			'usage': 0.95
		},
		"/var/opsi",
		{},
		{"state": 1, "message": "WARNING: DiskUsage warning from ressource: '/var/opsi' (available: 5.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"/var/opsi",
		{"warning": "30G", "critical": "10G"},
		{"state": 1, "message": "WARNING: DiskUsage warning from ressource: '/var/opsi' (available: 20.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"/var/opsi",
		{"warning": "30G", "critical": "20G"},
		{"state": 2, "message": "CRITICAL: DiskUsage from ressource: '/var/opsi' is critical (available: 20.00GB)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		["/var/opsi", "/var/log/opsi"],
		{"warning": "30G", "critical": "20G"},
		{"state": 2, "message": ("CRITICAL: DiskUsage from ressource: '/var/opsi' is critical (available: 20.00GB). "
		"DiskUsage from ressource: '/var/log/opsi' is critical (available: 20.00GB).")}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		["/var/opsi", "/var/log/opsi"],
		{"warning": "30%", "critical": "20%"},
		{"state": 2, "message": ("CRITICAL: DiskUsage from ressource: '/var/opsi' is critical (available: 20.00%). "
		"DiskUsage from ressource: '/var/log/opsi' is critical (available: 20.00%).")}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"/var/opsi",
		{"warning": "10%", "critical": "5%"},
		{"state": 0, "message": "OK: DiskUsage from ressource: '/var/opsi' is ok. (available: 20.00%)."}
	),
	(
		{
			'capacity': 107374182400,
			'available': 21474836480,
			'used': 85899345920,
			'usage': 0.80
		},
		"var/log/opsi",
		{"warning": "10%", "critical": "5%"},
		{"state": 0, "message": "OK: DiskUsage from ressource: '/var/log/opsi' is ok. (available: 20.00%)."}
	)

]

@pytest.mark.parametrize("info, opsiresource, thresholds, expected_result", test_data)
def test_check_disk_usage(info, opsiresource, thresholds, expected_result): # pylint: disable=too-many-arguments

	def get_info(path):
		print(path)
		return info

	with mock.patch('opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage', get_info):
		result = check_opsi_disk_usage(thresholds=thresholds, opsiresource=opsiresource)

	assert json.loads(result.body) == expected_result


def test_check_disk_usage_error(): # pylint: disable=too-many-arguments

	def get_info(path):
		raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)

	with mock.patch('opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage', get_info):
		result = check_opsi_disk_usage(opsiresource="/file/not/found")

	assert json.loads(result.body) == {
		'message': ('UNKNOWN: ["Not able to check DiskUsage. Error: \'[Errno 2] '
			'No such file or directory: \'/workspace/opsiconfd_data/static\'\'"]'),
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

	with mock.patch('opsiconfd.application.monitoring.check_opsi_disk_usage.getDiskSpaceUsage', get_info):
		result = check_opsi_disk_usage(opsiresource="/file/not/found")

	assert json.loads(result.body) == {
		'message': ('UNKNOWN: No results get. Nothing to check.'),
		'state': 3
		}
