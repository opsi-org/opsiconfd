# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
Tests for the opsiconfd monitoring module
"""

import asyncio
import json
import time
from typing import Any

import pytest

from opsiconfd.application.monitoring.utils import get_workers
from opsiconfd.config import get_depotserver_id
from opsiconfd.metrics.statistics import setup_metric_downsampling
from opsiconfd.redis import async_redis_client
from tests.monitoring.test_monitoring import (  # noqa: F401
	MONITORING_CHECK_DAYS,
	create_check_data,
)
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	clean_redis,
	config,
	test_client,
	worker_state,
)


@pytest.mark.parametrize(
	"product_ids, verbose, strict, expected_result",
	[
		(["unknown-product"], False, False, {"message": "OK: No Problem found for productIds: 'unknown-product'", "state": 0}),
		(
			["unknown-product", "pytest-prod-3"],
			False,
			False,
			{"message": "OK: No Problem found for productIds: 'unknown-product,pytest-prod-3'", "state": 0},
		),
		(
			["unknown-product", "pytest-prod-3"],
			True,
			False,
			{"message": "OK: No Problem found for productIds 'unknown-product,pytest-prod-3'", "state": 0},
		),
	],
)
def test_check_product_status_none(
	test_client: OpsiconfdTestClient,
	config: Config,
	product_ids: list[str],
	verbose: bool,
	strict: bool,
	expected_result: Any,  # noqa: F811  # noqa: F811
) -> None:
	data = json.dumps(
		{
			"task": "checkProductStatus",
			"param": {
				"task": "checkProductStatus",
				"http": False,
				"opsiHost": "localhost",
				"user": ADMIN_USER,
				"productIds": product_ids,
				"verbose": verbose,
				"strict": strict,
				"password": ADMIN_PASS,
				"port": 4447,
			},
		}
	)

	request = test_client.post(f"{config.internal_url}/monitoring", auth=(ADMIN_USER, ADMIN_PASS), content=data, timeout=5.0)
	assert request.status_code == 200
	assert request.json() == expected_result


@pytest.mark.parametrize(
	"products, verbose, strict, expected_result",
	[
		(
			["pytest-prod-1"],
			False,
			False,
			{
				"message": (
					f"WARNING: \nResult for Depot: '{get_depotserver_id()}':\n" "For product 'pytest-prod-1' action set on 1 clients!\n"
				),
				"state": 1,
			},
		),
		(
			["pytest-prod-2"],
			False,
			False,
			{
				"message": (
					"CRITICAL: \n"
					f"Result for Depot: '{get_depotserver_id()}':\n"
					"For product 'pytest-prod-2' problems found on 2 clients!\n"
				),
				"state": 2,
			},
		),
		(
			["pytest-prod-1", "pytest-prod-2"],
			False,
			False,
			{
				"message": (
					f"CRITICAL: \nResult for Depot: '{get_depotserver_id()}':\n"
					"For product 'pytest-prod-1' action set on 1 clients!\n"
					"For product 'pytest-prod-2' problems found on 2 clients!\n"
				),
				"state": 2,
			},
		),
		(["pytest-prod-3"], False, False, {"message": "OK: No Problem found for productIds: 'pytest-prod-3'", "state": 0}),
		(
			["pytest-prod-1", "pytest-prod-2", "pytest-prod-3"],
			False,
			False,
			{
				"message": (
					f"CRITICAL: \nResult for Depot: '{get_depotserver_id()}':\n"
					"For product 'pytest-prod-1' action set on 1 clients!\n"
					"For product 'pytest-prod-2' problems found on 2 clients!\n"
				),
				"state": 2,
			},
		),
	],
)
def test_check_product_status_not_none(
	test_client: OpsiconfdTestClient,
	config: Config,
	products: list[str],
	verbose: bool,
	strict: bool,
	expected_result: Any,  # noqa: F811  # noqa: F811
) -> None:
	data = json.dumps(
		{
			"task": "checkProductStatus",
			"param": {
				"task": "checkProductStatus",
				"http": False,
				"opsiHost": "localhost",
				"user": ADMIN_USER,
				"productIds": products,
				"verbose": verbose,
				"strict": strict,
				"password": ADMIN_PASS,
				"port": 4447,
			},
		}
	)
	request = test_client.post(f"{config.internal_url}/monitoring", auth=(ADMIN_USER, ADMIN_PASS), content=data, timeout=5.0)
	assert request.status_code == 200
	assert request.json() == expected_result


@pytest.mark.parametrize(
	"products, group, verbose, strict, expected_result",
	[
		(
			[],
			None,
			False,
			False,
			{
				"message": (
					"CRITICAL: \nResult for Depot: 'pytest-test-depot.uib.gmbh':\nFor product 'pytest-prod-1' action set on 1 clients!\n"
					"For product 'pytest-prod-2' problems found on 1 clients!\n"
					"\n"
					"Result for Depot: 'pytest-test-depot2.uib.gmbh':\n"
					"For product 'pytest-prod-4' action set on 1 clients!\n"
					"For product 'pytest-prod-4' version difference problems found on 1 clients!\n"
				),
				"state": 2,
			},
		),
		(
			[],
			[],
			False,
			False,
			{
				"message": (
					"CRITICAL: \nResult for Depot: 'pytest-test-depot.uib.gmbh':\nFor product 'pytest-prod-1' action set on 1 clients!\n"
					"For product 'pytest-prod-2' problems found on 1 clients!\n"
					"\n"
					"Result for Depot: 'pytest-test-depot2.uib.gmbh':\n"
					"For product 'pytest-prod-4' action set on 1 clients!\n"
					"For product 'pytest-prod-4' version difference problems found on 1 clients!\n"
				),
				"state": 2,
			},
		),
		(
			[],
			["pytest-group-1"],
			False,
			False,
			{
				"message": (
					"CRITICAL: \nResult for Depot: 'pytest-test-depot.uib.gmbh':\nFor product 'pytest-prod-1' action set on 1 clients!\n"
					"For product 'pytest-prod-2' problems found on 1 clients!\n"
				),
				"state": 2,
			},
		),
	],
)
def test_check_product_status_groupids(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
	products: list[str],
	group: list[str],
	verbose: bool,
	strict: bool,
	expected_result: Any,
) -> None:
	data = json.dumps(
		{
			"task": "checkProductStatus",
			"param": {
				"task": "checkProductStatus",
				"http": False,
				"opsiHost": "localhost",
				"user": ADMIN_USER,
				"productIds": products,
				"groupIds": group,
				"depotIds": ["pytest-test-depot.uib.gmbh", "pytest-test-depot2.uib.gmbh"],
				"verbose": verbose,
				"strict": strict,
				"password": ADMIN_PASS,
				"port": 4447,
			},
		}
	)
	request = test_client.post(f"{config.internal_url}/monitoring", auth=(ADMIN_USER, ADMIN_PASS), content=data, timeout=5.0)
	assert request.status_code == 200
	assert request.json() == expected_result


@pytest.mark.parametrize(
	"product, expected_result",
	[
		(
			"pytest-prod-1",
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
			{
				"message": (
					"CRITICAL: 3 ProductStates for product: 'pytest-prod-2' found; "
					"checking for Version: '1.0' and Package: '1'; Problems found on 3 clients"
				),
				"state": 2,
			},
		),
		(
			"pytest-prod-3",
			{
				"message": ("OK: 1 ProductStates for product: 'pytest-prod-3' found; " "checking for Version: '1.0' and Package: '1'"),
				"state": 0,
			},
		),
	],
)
def test_check_product_status_short(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
	product: str,
	expected_result: Any,
) -> None:
	data = json.dumps(
		{
			"task": "checkShortProductStatus",
			"param": {
				"task": "checkShortProductStatus",
				"http": False,
				"opsiHost": "localhost",
				"user": ADMIN_USER,
				"productId": product,
				"password": ADMIN_PASS,
				"port": 4447,
			},
		}
	)

	request = test_client.post(f"{config.internal_url}/monitoring", auth=(ADMIN_USER, ADMIN_PASS), content=data, timeout=5.0)
	assert request.status_code == 200
	assert request.json() == expected_result


@pytest.mark.parametrize(
	"client, exclude, expected_result",
	[
		(
			"pytest-lost-client.uib.local",
			None,
			{
				"message": (
					f"WARNING: opsi-client pytest-lost-client.uib.local has not been seen, since {MONITORING_CHECK_DAYS} days. "
					"Please check opsi-client-agent installation on client or perhaps a client that can be deleted. "
				),
				"state": 1,
			},
		),
		(
			"pytest-lost-client-fp.uib.local",
			None,
			{
				"message": (
					f"CRITICAL: opsi-client pytest-lost-client-fp.uib.local has not been seen, since {MONITORING_CHECK_DAYS} days. "
					"Please check opsi-client-agent installation on client or perhaps a client that can be deleted. "
					"Products: 'pytest-prod-2' are in failed state. "
				),
				"state": 2,
			},
		),
		(
			"pytest-lost-client-fp2.uib.local",
			None,
			{
				"message": (
					f"CRITICAL: opsi-client pytest-lost-client-fp2.uib.local has not been seen, since {MONITORING_CHECK_DAYS} days. "
					"Please check opsi-client-agent installation on client or perhaps a client that can be deleted. "
					"Products: 'pytest-prod-2' are in failed state. "
					"Actions set for products: 'pytest-prod-1 (setup)'."
				),
				"state": 2,
			},
		),
		(
			"pytest-client-1.uib.local",
			None,
			{
				"message": (
					"WARNING: opsi-client pytest-client-1.uib.local has been seen today. "
					"Actions set for products: 'pytest-prod-1 (setup)'."
				),
				"state": 1,
			},
		),
		(
			"pytest-client-2.uib.local",
			None,
			{
				"message": (
					"CRITICAL: opsi-client pytest-client-2.uib.local has been seen today. "
					"Products: 'pytest-prod-2' are in failed state. "
				),
				"state": 2,
			},
		),
		(
			"pytest-client-3.uib.local",
			None,
			{
				"message": (
					"OK: opsi-client pytest-client-3.uib.local has been seen today. " "No failed products and no actions set for client"
				),
				"state": 0,
			},
		),
		(
			"this-is-not-a-client.uib.local",
			None,
			{"message": "UNKNOWN: opsi-client: 'this-is-not-a-client.uib.local' not found", "state": 3},
		),
		(
			"pytest-client-1.uib.local",
			["pytest-prod-1"],
			{
				"message": (
					"OK: opsi-client pytest-client-1.uib.local has been seen today. " "No failed products and no actions set for client"
				),
				"state": 0,
			},
		),
		(
			"pytest-client-2.uib.local",
			["pytest-prod-2"],
			{
				"message": (
					"OK: opsi-client pytest-client-2.uib.local has been seen today. " "No failed products and no actions set for client"
				),
				"state": 0,
			},
		),
	],
)
def test_check_client_status(
	test_client: OpsiconfdTestClient,
	config: Config,
	client: str,
	exclude: list[str],
	expected_result: Any,  # noqa: F811  # noqa: F811
) -> None:
	data = json.dumps(
		{
			"task": "checkClientStatus",
			"param": {
				"task": "checkClientStatus",
				"http": False,
				"opsiHost": "localhost",
				"user": ADMIN_USER,
				"clientId": client,
				"exclude": exclude,
				"password": ADMIN_PASS,
				"port": 4447,
			},
		}
	)

	request = test_client.post(f"{config.internal_url}/monitoring", auth=(ADMIN_USER, ADMIN_PASS), content=data, timeout=5.0)
	assert request.status_code == 200
	assert request.json() == expected_result


@pytest.mark.parametrize(
	"depot_ids, product_ids, exclude, strict, verbose, expected_result",
	[
		(
			[get_depotserver_id(), "pytest-test-depot.uib.gmbh"],
			["pytest-prod-1", "pytest-prod-2"],
			[],
			False,
			False,
			{"message": f"OK: Syncstate ok for depots {get_depotserver_id()}, pytest-test-depot.uib.gmbh", "state": 0},
		),
		(
			[get_depotserver_id(), "pytest-test-depot.uib.gmbh"],
			["pytest-prod-1", "pytest-prod-2"],
			[],
			True,
			False,
			{"message": f"OK: Syncstate ok for depots {get_depotserver_id()}, pytest-test-depot.uib.gmbh", "state": 0},
		),
		(
			[get_depotserver_id(), "pytest-test-depot.uib.gmbh"],
			["pytest-prod-1", "pytest-prod-2"],
			[],
			False,
			True,
			{"message": f"OK: Syncstate ok for depots {get_depotserver_id()}, pytest-test-depot.uib.gmbh", "state": 0},
		),
		(
			[get_depotserver_id(), "pytest-test-depot.uib.gmbh"],
			["pytest-prod-1", "pytest-prod-2"],
			[],
			True,
			True,
			{"message": f"OK: Syncstate ok for depots {get_depotserver_id()}, pytest-test-depot.uib.gmbh", "state": 0},
		),
		(
			[get_depotserver_id(), "pytest-test-depot2.uib.gmbh"],
			["pytest-prod-1", "pytest-prod-2"],
			[],
			False,
			False,
			{"message": "WARNING: Differences found for 1 products", "state": 1},
		),
		(
			[get_depotserver_id(), "pytest-test-depot2.uib.gmbh"],
			["pytest-prod-1", "pytest-prod-2"],
			[],
			False,
			True,
			{
				"message": (
					"WARNING: Differences found for 1 products:\n"
					f"product 'pytest-prod-1': {get_depotserver_id()} (1.0-1) \n"
					"pytest-test-depot2.uib.gmbh (2.0-1) \n"
				),
				"state": 1,
			},
		),
		(
			[get_depotserver_id(), "pytest-test-depot2.uib.gmbh"],
			["pytest-prod-1", "pytest-prod-2", "pytest-prod-3"],
			[],
			True,
			True,
			{
				"message": (
					"WARNING: Differences found for 1 products:\n"
					f"product 'pytest-prod-1': {get_depotserver_id()} (1.0-1) \n"
					"pytest-test-depot2.uib.gmbh (2.0-1) \n"
				),
				"state": 1,
			},
		),
		(
			["pytest-test-depot2.uib.gmbh", get_depotserver_id()],
			["pytest-prod-1", "pytest-prod-2", "pytest-prod-3"],
			[],
			True,
			True,
			{
				"message": (
					"WARNING: Differences found for 1 products:\n"
					"product 'pytest-prod-1': pytest-test-depot2.uib.gmbh (2.0-1) \n"
					f"{get_depotserver_id()} (1.0-1) \n"
				),
				"state": 1,
			},
		),
		(
			["pytest-test-depot2.uib.gmbh", get_depotserver_id()],
			["pytest-prod-1", "pytest-prod-2", "pytest-prod-3"],
			["pytest-prod-3"],
			True,
			True,
			{
				"message": (
					"WARNING: Differences found for 1 products:\n"
					"product 'pytest-prod-1': pytest-test-depot2.uib.gmbh (2.0-1) \n"
					f"{get_depotserver_id()} (1.0-1) \n"
				),
				"state": 1,
			},
		),
	],
)
def test_check_depot_sync_status(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
	depot_ids: list[str],
	product_ids: list[str],
	exclude: list[str],
	strict: bool,
	verbose: bool,
	expected_result: Any,
) -> None:
	data = json.dumps(
		{
			"task": "checkDepotSyncStatus",
			"param": {
				"task": "checkDepotSyncStatus",
				"http": False,
				"opsiHost": "localhost",
				"user": ADMIN_USER,
				"depotIds": depot_ids,
				"productIds": product_ids,
				"exclude": exclude,
				"strict": strict,
				"verbose": verbose,
				"password": ADMIN_PASS,
				"port": 4447,
			},
		}
	)

	request = test_client.post(f"{config.internal_url}/monitoring", auth=(ADMIN_USER, ADMIN_PASS), content=data, timeout=5.0)
	assert request.status_code == 200
	assert request.json() == expected_result


@pytest.mark.parametrize(
	"cpu_thresholds, error_thresholds, perfdata, cpu_value, expected_result",
	[
		({"critical": 100, "warning": 100}, None, False, 99, {"message": "OK: Opsi Webservice has no Problem.", "state": 0}),
		({"critical": 100, "warning": 50}, None, False, 99, {"message": "WARNING: CPU-Usage over 50%", "state": 1}),
		(
			{"critical": 70, "warning": 50},
			None,
			False,
			99,
			{"message": "CRITICAL: CPU-Usage over 70%", "state": 2},
		),
	],
)
async def test_check_opsi_webservice_cpu(
	worker_state: Any,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
	cpu_thresholds: dict[str, int],
	error_thresholds: dict[str, int],
	perfdata: bool,
	cpu_value: int,
	expected_result: Any,
) -> None:
	setup_metric_downsampling()
	data = json.dumps(
		{
			"task": "checkOpsiWebservice",
			"param": {
				"task": "checkOpsiWebservice",
				"http": False,
				"opsiHost": "localhost",
				"user": ADMIN_USER,
				"cpu": cpu_thresholds,
				"errors": error_thresholds,
				"perfdata": perfdata,
				"password": ADMIN_PASS,
				"port": 4447,
			},
		}
	)

	redis = await async_redis_client()
	workers = await get_workers(redis)
	timestamp = int(time.time() - 100)
	for _ in range(200):
		timestamp += 1
		for worker in workers:
			await redis.execute_command(  # type: ignore[no-untyped-call]
				f"TS.ADD {config.redis_key('stats')}:worker:avg_cpu_percent:{worker} {timestamp*1000} {cpu_value} ON_DUPLICATE LAST"
			)

	await asyncio.sleep(1)

	request = test_client.post(f"{config.internal_url}/monitoring", auth=(ADMIN_USER, ADMIN_PASS), content=data, timeout=5.0)
	assert request.status_code == 200
	assert request.json() == expected_result
