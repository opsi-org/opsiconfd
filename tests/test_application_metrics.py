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
import time

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
from opsiconfd.statistics import setup_metric_downsampling
from opsiconfd.utils import async_redis_client
from opsiconfd.worker import Worker

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	clean_redis,
	config,
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


async def create_ts_data(
	node_name: str, postfix: str, start: int, end: int, interval: int, value: float, delete: bool = True
):  # pylint: disable=too-many-locals,too-many-arguments
	# avg_cpu_percent
	#   retention: 2 * 3600 * 1000 = 7200000
	#   downsampling:
	#      ["minute", 24 * 3600 * 1000, "avg"]
	#      ["hour", 60 * 24 * 3600 * 1000, "avg"]
	#      ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]

	redis = await async_redis_client()
	if postfix:
		redis_key = f"opsiconfd:stats:worker:avg_cpu_percent:{node_name}:1:{postfix}"
	else:
		redis_key = f"opsiconfd:stats:worker:avg_cpu_percent:{node_name}:1"

	if delete:
		async for key in redis.scan_iter("opsiconfd:stats:worker:avg_cpu_percent:*"):
			await redis.delete(key)
		await redis.delete("opsiconfd:stats:worker:avg_cpu_percent")

		await asyncio.sleep(3)
		setup_metric_downsampling()
		await asyncio.sleep(3)

	# Do not use a pipeline here (will kill redis-server)
	seconds = end - start
	samples = int(seconds / interval)
	for sample_num in range(samples):
		second = sample_num * interval
		timestamp = start + second
		cmd = (
			"TS.ADD",
			redis_key,
			timestamp * 1000,
			value,
			"RETENTION",
			7200000,
			"ON_DUPLICATE",
			"SUM",
			"LABELS",
			"node_name",
			node_name,
			"worker_num",
			1,
		)
		await redis.execute_command(" ".join([str(x) for x in cmd]))


@pytest.mark.grafana_available
async def test_grafana_query_end_current_time(test_client, config):  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	end = int(time.time())
	value = 10

	await create_ts_data(config.node_name, "", end - 3600, end, 5, value)
	await create_ts_data(config.node_name, "minute", end - 23 * 3600, end, 60, value, False)

	seconds = 300
	_to = datetime.datetime.fromtimestamp(end)
	_from = _to - datetime.timedelta(seconds=seconds)
	query = {
		"app": "dashboard",
		"range": {"from": f"{_from.isoformat()}Z", "to": f"{_to.isoformat()}Z", "raw": {"from": f"now-{seconds}s", "to": "now"}},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [{"type": "timeserie", "target": f"opsiconfd:stats:worker:avg_cpu_percent:{config.node_name}:1", "refId": "A"}],
	}

	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()
	num_values = len(data[0]["datapoints"])
	expected_values = seconds / 5

	assert expected_values - 1 <= num_values <= expected_values + 1
	assert data[0]["datapoints"][0][1] >= (_from.timestamp() - 5) * 1000
	assert data[0]["datapoints"][-1][1] <= (_to.timestamp() + 5) * 1000
	for dat in data[0]["datapoints"]:
		assert dat[0] == value

	# Downsampling (minute)
	seconds = 10 * 3600
	_to = datetime.datetime.fromtimestamp(end)
	_from = _to - datetime.timedelta(seconds=seconds)
	query = {
		"app": "dashboard",
		"range": {"from": f"{_from.isoformat()}Z", "to": f"{_to.isoformat()}Z", "raw": {"from": f"now-{seconds}s", "to": "now"}},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [{"type": "timeserie", "target": f"opsiconfd:stats:worker:avg_cpu_percent:{config.node_name}:1", "refId": "A"}],
	}

	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()
	num_values = len(data[0]["datapoints"])
	expected_values = seconds / 60

	assert expected_values - 1 <= num_values <= expected_values + 1
	assert data[0]["datapoints"][0][1] >= (_from.timestamp() - 60) * 1000
	assert data[0]["datapoints"][-1][1] <= (_to.timestamp() + 60) * 1000
	for dat in data[0]["datapoints"]:
		assert dat[0] == value

	# minute, end one hour in the past
	seconds = 10 * 3600
	_to = datetime.datetime.fromtimestamp(end) - datetime.timedelta(seconds=3600)
	_from = _to - datetime.timedelta(seconds=seconds)
	query = {
		"app": "dashboard",
		"range": {"from": f"{_from.isoformat()}Z", "to": f"{_to.isoformat()}Z", "raw": {"from": f"now-{seconds}s", "to": "now"}},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [{"type": "timeserie", "target": f"opsiconfd:stats:worker:avg_cpu_percent:{config.node_name}:1", "refId": "A"}],
	}

	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()
	num_values = len(data[0]["datapoints"])
	expected_values = seconds / 60

	assert expected_values - 1 <= num_values <= expected_values + 1
	assert data[0]["datapoints"][0][1] >= (_from.timestamp() - 60) * 1000
	assert data[0]["datapoints"][-1][1] <= (_to.timestamp() + 60) * 1000
	for dat in data[0]["datapoints"]:
		assert dat[0] == value


async def test_grafana_query_interval_in_past(test_client, config):  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	end = int(time.time())
	await create_ts_data(config.node_name, "minute", end - 23 * 3600, end, 60, 20)
	await create_ts_data(config.node_name, "hour", end - 35 * 3600, end, 3600, 40, False)

	# Interval (from -> to) is one hour and should use minutes
	# but 30h ago the minutes should be deleted so hours should be used
	# grafana seconds: seconds to go back in time (now-grafana seconds)
	grafana_seconds = 30 * 3600
	end = int(time.time()) - grafana_seconds
	seconds = 3600

	_to = datetime.datetime.fromtimestamp(end)
	_from = _to - datetime.timedelta(seconds=seconds)

	query = {
		"app": "dashboard",
		"range": {
			"from": f"{_from.isoformat()}Z",
			"to": f"{_to.isoformat()}Z",
			"raw": {"from": f"now-{grafana_seconds + seconds}s", "to": f"now-{grafana_seconds}s"},
		},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [{"type": "timeserie", "target": f"opsiconfd:stats:worker:avg_cpu_percent:{config.node_name}:1", "refId": "A"}],
	}

	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()

	assert data[0]["datapoints"] != []
	for dat in data[0]["datapoints"]:
		assert dat[0] == 40
