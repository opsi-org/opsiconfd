# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

'''
Tests for the opsiconfd monitoring module
using https requests
'''

import sys
import json

import socket
import asyncio

import pytest
import requests
import aredis

from opsiconfd.application.monitoring.utils import get_workers
from opsiconfd.utils import decode_redis_result
from .utils import clean_redis, config, create_check_data, TEST_USER, TEST_PW, HOSTNAME, LOCAL_IP, DAYS # pylint: disable=unused-import



@pytest.fixture(name="config")
def fixture_config(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel, redefined-outer-name
	return config





test_data = [
	(
		["unknown-product"],
		False,
		False,
		{'message': "OK: No Problem found for productIds: 'unknown-product'", 'state': 0}
	),
	(
		["unknown-product", "pytest-prod-3"],
		False,
		False,
		{'message': "OK: No Problem found for productIds: 'unknown-product,pytest-prod-3'", 'state': 0}
	),
	(
		["unknown-product", "pytest-prod-3"],
		True,
		False,
		{'message': "OK: No Problem found for productIds 'unknown-product,pytest-prod-3'", 'state': 0}
	)
]

@pytest.mark.parametrize("product_ids, verbose, strict, expected_result", test_data)
def test_check_product_status_none(config, product_ids, verbose, strict, expected_result):

	data = json.dumps({
		'task': 'checkProductStatus',
		'param': {
			'task': 'checkProductStatus',
			'http': False,
			'opsiHost': 'localhost',
			'user': TEST_USER,
			'productIds': product_ids,
			'verbose': verbose,
			'strict': strict,
			'password': TEST_PW,
			'port': 4447
		}
	})

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result


test_data = [
	(
		["pytest-prod-1"],
		False,
		False,
		{
			'message': (f"WARNING: \nResult for Depot: '{socket.getfqdn()}':\n"
				"For product 'pytest-prod-1' action set on 1 clients!\n"),
			'state': 1
		}
	),
	(
		["pytest-prod-2"],
		False,
		False,
		{
			'message': ("CRITICAL: \n"
				f"Result for Depot: '{socket.getfqdn()}':\n"
				"For product 'pytest-prod-2' problems found on 2 clients!\n"),
			'state': 2
		}
	),
	(
		["pytest-prod-1","pytest-prod-2"],
		False,
		False,
		{
			'message': (f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\n"
				"For product 'pytest-prod-1' action set on 1 clients!\n"
				"For product 'pytest-prod-2' problems found on 2 clients!\n"),
			'state': 2
		}
	),
	(
		["pytest-prod-3"],
		False,
		False,
		{
			'message': "OK: No Problem found for productIds: 'pytest-prod-3'",
			'state': 0
		}
	),
	(
		["pytest-prod-1","pytest-prod-2","pytest-prod-3"],
		False,
		False,
		{
			'message': (f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\n"
				"For product 'pytest-prod-1' action set on 1 clients!\n"
				"For product 'pytest-prod-2' problems found on 2 clients!\n"),
			'state': 2
		}
	)
]


@pytest.mark.parametrize("products, verbose, strict, expected_result", test_data)
def test_check_product_status(config, products, verbose, strict, expected_result):

	data = json.dumps({
		'task': 'checkProductStatus',
		'param': {
			'task': 'checkProductStatus',
			'http': False,
			'opsiHost': 'localhost',
			'user': TEST_USER,
			'productIds': products,
			'verbose': verbose,
			'strict': strict,
			'password': TEST_PW,
			'port': 4447
		}
	})
	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result


test_data = [
	(
		[],
		None,
		False,
		False,
		{
			'message': (
				f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-1' action set on 1 clients!\n"
				"For product 'pytest-prod-2' problems found on 2 clients!\n"
			),
			'state': 2
		}
	),
	(
		[],
		[],
		False,
		False,
		{
			'message': (
				f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-1' action set on 1 clients!\n"
				"For product 'pytest-prod-2' problems found on 2 clients!\n"
			),
			'state': 2
		}
	),
	(
		[],
		["pytest-group-1"],
		False,
		False,
		{
			'message': (
				f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-1' action set on 1 clients!\n"
				"For product 'pytest-prod-2' problems found on 2 clients!\n"
			),
			'state': 2
		}
	)
]
@pytest.mark.parametrize("products, group, verbose, strict, expected_result", test_data)
def test_check_product_status_groupids(config, products, group,verbose, strict, expected_result):


	data = json.dumps({
		'task': 'checkProductStatus',
		'param': {
			'task': 'checkProductStatus',
			'http': False,
			'opsiHost': 'localhost',
			'user': TEST_USER,
			'productIds': products,
			'groupIds': group,
			'verbose': verbose,
			'strict': strict,
			'password': TEST_PW,
			'port': 4447
		}
	})
	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result


test_data = [
	(
		"pytest-prod-1",
		{
			'message': ("WARNING: 2 ProductStates for product: 'pytest-prod-1' found; "
				"checking for Version: '1.0' and Package: '1'; ActionRequest set on 2 clients"),
			'state': 1
		}
	),
	(
		"pytest-prod-2",
		{
			'message': ("CRITICAL: 3 ProductStates for product: 'pytest-prod-2' found; "
				"checking for Version: '1.0' and Package: '1'; Problems found on 3 clients"),
			'state': 2
		}
	),
	(
		"pytest-prod-3",
		{
			'message':  ("OK: 1 ProductStates for product: 'pytest-prod-3' found; "
				"checking for Version: '1.0' and Package: '1'"),
			'state': 0
		}
	)
]


@pytest.mark.parametrize("product, expected_result", test_data)
def test_check_product_status_short(config, product, expected_result):

	data = json.dumps({'task': 'checkShortProductStatus', 'param': {'task': 'checkShortProductStatus', 'http': False, 'opsiHost': 'localhost', 'user': TEST_USER, 'productId': product, 'password': TEST_PW, 'port': 4447}}) # pylint: disable=line-too-long

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result


test_data = [
	("pytest-lost-client.uib.local", None, {
		'message': (f"WARNING: opsi-client pytest-lost-client.uib.local has not been seen, since {DAYS} days. "
			"Please check opsi-client-agent installation on client or perhaps a client that can be deleted. "),
		'state': 1
	}),
	("pytest-lost-client-fp.uib.local", None, {
		'message': (f"CRITICAL: opsi-client pytest-lost-client-fp.uib.local has not been seen, since {DAYS} days. "
			"Please check opsi-client-agent installation on client or perhaps a client that can be deleted. "
			"Products: 'pytest-prod-2' are in failed state. "),
		'state': 2
	}),
	("pytest-lost-client-fp2.uib.local", None, {
		'message': (f"CRITICAL: opsi-client pytest-lost-client-fp2.uib.local has not been seen, since {DAYS} days. "
			"Please check opsi-client-agent installation on client or perhaps a client that can be deleted. "
			"Products: 'pytest-prod-2' are in failed state. "
			"Actions set for products: 'pytest-prod-1 (setup)'."),
		'state': 2
	}),
	("pytest-client-1.uib.local", None, {
		'message': ("WARNING: opsi-client pytest-client-1.uib.local has been seen today. "
			"Actions set for products: 'pytest-prod-1 (setup)'."),
		'state': 1
	}),
	("pytest-client-2.uib.local", None, {
		'message': ("CRITICAL: opsi-client pytest-client-2.uib.local has been seen today. "
			"Products: 'pytest-prod-2' are in failed state. "),
		'state': 2
	}),
	("pytest-client-3.uib.local", None, {
		'message': ("OK: opsi-client pytest-client-3.uib.local has been seen today. "
			"No failed products and no actions set for client"),
		'state': 0
	}),
	("this-is-not-a-client.uib.local", None, {
		'message': "UNKNOWN: opsi-client: 'this-is-not-a-client.uib.local' not found",
		'state': 3
	}),
	("pytest-client-1.uib.local", ["pytest-prod-1"], {
		'message': ("OK: opsi-client pytest-client-1.uib.local has been seen today. "
			"No failed products and no actions set for client"),
		'state': 0
	}),
	("pytest-client-2.uib.local", ["pytest-prod-2"], {
		'message': ("OK: opsi-client pytest-client-2.uib.local has been seen today. "
			"No failed products and no actions set for client"),
		'state': 0
	})

]
@pytest.mark.parametrize("client, exclude, expected_result", test_data)
def test_check_client_status(config, client, exclude, expected_result):

	data = json.dumps({
		'task': 'checkClientStatus',
		'param': {
			'task': 'checkClientStatus',
			'http': False,
			'opsiHost': 'localhost',
			'user': TEST_USER,
			'clientId': client,
			'exclude': exclude,
			'password': TEST_PW,
			'port': 4447
			}
	})

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result


test_data = [
	(
		[socket.getfqdn(), "pytest-test-depot.uib.gmbh" ],
		["pytest-prod-1","pytest-prod-2"],
		[],
		False,
		False,
		{
			"message": f"OK: Syncstate ok for depots {socket.getfqdn()}, pytest-test-depot.uib.gmbh",
			"state": 0
		}
	),
	(
		[socket.getfqdn(), "pytest-test-depot.uib.gmbh" ],
		["pytest-prod-1","pytest-prod-2"],
		[],
		True,
		False,
		{
			"message": f"OK: Syncstate ok for depots {socket.getfqdn()}, pytest-test-depot.uib.gmbh",
			"state": 0
		}
	),
	(
		[socket.getfqdn(), "pytest-test-depot.uib.gmbh" ],
		["pytest-prod-1","pytest-prod-2"],
		[],
		False,
		True,
		{
			"message": f"OK: Syncstate ok for depots {socket.getfqdn()}, pytest-test-depot.uib.gmbh",
			"state": 0
		}
	),
	(
		[socket.getfqdn(), "pytest-test-depot.uib.gmbh" ],
		["pytest-prod-1","pytest-prod-2"],
		[],
		True,
		True,
		{
			"message": f"OK: Syncstate ok for depots {socket.getfqdn()}, pytest-test-depot.uib.gmbh",
			"state": 0
		}
	),
	(
		[socket.getfqdn(), "pytest-test-depot2.uib.gmbh" ],
		["pytest-prod-1","pytest-prod-2"],
		[],
		False,
		False,
		{
			'message': 'WARNING: Differences found for 1 products',
			'state': 1
		}
	),
	(
		[socket.getfqdn(), "pytest-test-depot2.uib.gmbh" ],
		["pytest-prod-1","pytest-prod-2"],
		[],
		False,
		True,
		{
			'message': ("WARNING: Differences found for 1 products:\n"
			f"product 'pytest-prod-1': {socket.getfqdn()} (1.0-1) \n"
			"pytest-test-depot2.uib.gmbh (2.0-1) \n"),
			'state': 1
		}
	),
	(
		[socket.getfqdn(), "pytest-test-depot2.uib.gmbh" ],
		["pytest-prod-1","pytest-prod-2","pytest-prod-3"],
		[],
		True,
		True,
		{
			'message': ("WARNING: Differences found for 1 products:\n"
			f"product 'pytest-prod-1': {socket.getfqdn()} (1.0-1) \n"
			"pytest-test-depot2.uib.gmbh (2.0-1) \n"),
			'state': 1
		}
	),
	(
		["pytest-test-depot2.uib.gmbh", socket.getfqdn()],
		["pytest-prod-1","pytest-prod-2","pytest-prod-3"],
		[],
		True,
		True,
		{
			'message': ("WARNING: Differences found for 1 products:\n"
			"product 'pytest-prod-1': pytest-test-depot2.uib.gmbh (2.0-1) \n"
			f"{socket.getfqdn()} (1.0-1) \n"),
			'state': 1
		}
	)
	,
	(
		["pytest-test-depot2.uib.gmbh", socket.getfqdn()],
		["pytest-prod-1","pytest-prod-2","pytest-prod-3"],
		["pytest-prod-3"],
		True,
		True,
		{
			'message': ("WARNING: Differences found for 1 products:\n"
			"product 'pytest-prod-1': pytest-test-depot2.uib.gmbh (2.0-1) \n"
			f"{socket.getfqdn()} (1.0-1) \n"),
			'state': 1
		}
	)
]
@pytest.mark.parametrize("depot_ids, product_ids, exclude, strict, verbose, expected_result", test_data)
def test_check_depot_sync_status(config, depot_ids, product_ids, exclude, strict, verbose, expected_result): # pylint: disable=too-many-arguments

	data = json.dumps({
		'task': 'checkDepotSyncStatus',
		'param': {
			'task': 'checkDepotSyncStatus',
			'http': False,
			'opsiHost': 'localhost',
			'user': TEST_USER,
			'depotIds': depot_ids,
			'productIds': product_ids,
			'exclude': exclude,
			'strict': strict,
			'verbose': verbose,
			'password': TEST_PW,
			'port': 4447
			}
	})

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result


test_data = [
	(
		None,
		None,
		False,
		{
			"message": 'OK: Opsi Webservice has no Problem.',
			"state": 0
		}
	)
]
@pytest.mark.parametrize("cpu_thresholds, error_thresholds, perfdata, expected_result", test_data)
def test_check_opsi_webservice(config, cpu_thresholds, error_thresholds, perfdata, expected_result): # pylint: disable=too-many-arguments

	data = json.dumps({
		'task': 'checkOpsiWebservice',
		'param': {
			'task': 'checkOpsiWebservice',
			'http': False,
			'opsiHost': 'localhost',
			'user': TEST_USER,
			'cpu_thresholds': cpu_thresholds,
			'error_thresholds': error_thresholds,
			'perfdata': perfdata,
			'password': TEST_PW,
			'port': 4447
			}
	})

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result


test_data = [
	(
		None,
		None,
		True
	)
]
@pytest.mark.parametrize("cpu_thresholds, error_thresholds, perfdata", test_data)
def test_check_opsi_webservice_perfdata(config, cpu_thresholds, error_thresholds, perfdata): # pylint: disable=too-many-arguments

	data = json.dumps({
		'task': 'checkOpsiWebservice',
		'param': {
			'task': 'checkOpsiWebservice',
			'http': False,
			'opsiHost': 'localhost',
			'user': TEST_USER,
			'cpu_thresholds': cpu_thresholds,
			'error_thresholds': error_thresholds,
			'perfdata': perfdata,
			'password': TEST_PW,
			'port': 4447
			}
	})

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json().get("state") ==  0
	assert request.json().get("message").startswith('OK: Opsi Webservice has no Problem. |')


test_data = [
	(
		None,
		None,
		False,
		100,
		{
			"message": 'CRITICAL: CPU-Usage over 80%',
			"state": 2
		}
	),
	(
		{"critical": 60, "warning": 50},
		None,
		False,
		100,
		{
			"message": 'CRITICAL: CPU-Usage over 60%',
			"state": 2
		}
	),
	(
		{"critical": 99, "warning": 55},
		None,
		False,
		100,
		{
			"message": 'WARNING: CPU-Usage over 55%',
			"state": 1
		}
	)
]
@pytest.mark.asyncio
@pytest.mark.parametrize("cpu_thresholds, error_thresholds, perfdata, cpu_value, expected_result", test_data)
async def test_check_opsi_webservice_cpu(config, cpu_thresholds, error_thresholds, perfdata, cpu_value,expected_result): # pylint: disable=too-many-arguments

	data = json.dumps({
		'task': 'checkOpsiWebservice',
		'param': {
			'task': 'checkOpsiWebservice',
			'http': False,
			'opsiHost': 'localhost',
			'user': TEST_USER,
			'cpu': cpu_thresholds,
			'errors': error_thresholds,
			'perfdata': perfdata,
			'password': TEST_PW,
			'port': 4447
			}
	})

	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)

	workers = await get_workers(redis_client)
	count = 0
	while True:
		count += 1
		await asyncio.sleep(0.1)
		for worker in workers:
			await redis_client.execute_command(f"TS.ADD opsiconfd:stats:worker:avg_cpu_percent:{worker} * {cpu_value} ON_DUPLICATE SUM")
		if count > 650:
			break

	await asyncio.sleep(0.5)

	# for worker in workers:
	value = await redis_client.execute_command(f"TS.GET opsiconfd:stats:worker:avg_cpu_percent:{workers[0]}:minute")
	print(decode_redis_result(value)[1])

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result
