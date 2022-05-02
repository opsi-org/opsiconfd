# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.metrics
"""

import asyncio
import datetime

import pytest

from opsiconfd.application.metrics import (
	get_clients,
	get_nodes,
	get_workers,
	grafana_dashboard,
	grafana_dashboard_config,
	grafana_search,
)
from opsiconfd.metrics import WorkerMetricsCollector
from opsiconfd.utils import async_redis_client
from opsiconfd.worker import Worker

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	clean_redis,
	test_client,
)


async def _register_workers():
	node_name = "testnode"
	workers = (
		{"node_name": node_name, "pid": 121, "worker_num": 1},
		{"node_name": node_name, "pid": 122, "worker_num": 2},
		{"node_name": node_name, "pid": 123, "worker_num": 3},
	)
	redis = await async_redis_client()
	for worker in workers:
		redis_key = f"opsiconfd:worker_registry:{node_name}:{worker['worker_num']}"
		await redis.hset(
			redis_key,
			key=None,
			value=None,
			mapping={"worker_pid": worker["pid"], "node_name": worker["node_name"], "worker_num": worker["worker_num"]},
		)
		await redis.expire(redis_key, 5)
	return workers


async def test_get_workers():
	workers = await _register_workers()
	_workers = await get_workers()
	for worker in workers:
		found = False
		for _worker in _workers:
			if (
				_worker["node_name"] == worker["node_name"]  # pylint: disable=loop-invariant-statement
				and _worker["worker_num"] == worker["worker_num"]  # pylint: disable=loop-invariant-statement
			):
				found = True
				break
		if not found:
			raise Exception(f"Worker {worker} not found")


async def test_get_nodes():
	workers = await _register_workers()
	nodes = await get_nodes()
	for worker in workers:
		assert worker["node_name"] in nodes


async def test_get_clients(test_client):  # pylint: disable=redefined-outer-name
	worker = Worker()
	worker.metrics_collector = WorkerMetricsCollector(worker)
	worker.metrics_collector._interval = 1  # pylint: disable=protected-access
	loop = asyncio.get_event_loop()
	loop.create_task(worker.metrics_collector.main_loop())
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	rpc = {"id": 1, "method": "backend_info", "params": []}
	res = test_client.post("/rpc", json=rpc)
	assert res.status_code == 200
	await asyncio.sleep(1)
	worker.metrics_collector.stop()
	await asyncio.sleep(1)
	clients = await get_clients("client:sum_http_request_number")
	assert clients == [{"client_addr": "127.0.0.1"}]


@pytest.mark.grafana_available
async def test_grafana_dashboard():
	res = await grafana_dashboard()
	assert res.headers["location"].endswith("/d/opsiconfd_main/opsiconfd-main-dashboard?kiosk=tv")
	assert res.status_code == 307


async def test_grafana_dashboard_config():
	conf = await grafana_dashboard_config()
	assert len(conf["panels"]) == 10


async def test_grafana_search():
	workers = await _register_workers()
	res = await grafana_search()
	for worker in workers:
		assert f"Average CPU usage of worker {worker['worker_num']} on {worker['node_name']}" in res


async def test_grafana_query(test_client):  # pylint: disable=redefined-outer-name
	worker = Worker()
	worker.metrics_collector = WorkerMetricsCollector(worker)
	worker.metrics_collector._interval = 1  # pylint: disable=protected-access
	loop = asyncio.get_event_loop()
	loop.create_task(worker.metrics_collector.main_loop())
	await asyncio.sleep(2)

	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	_to = datetime.datetime.utcnow()
	_from = _to - datetime.timedelta(hours=24)
	query = {
		"app": "dashboard",
		"range": {"from": f"{_from.isoformat()}Z", "to": f"{_to.isoformat()}Z", "raw": {"from": "now-24h", "to": "now"}},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [{"type": "timeserie", "target": "Average system load on localhost", "refId": "A"}],
	}
	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()
	assert len(data[0]["datapoints"]) > 0
	assert len(data[0]["datapoints"][0]) == 2
