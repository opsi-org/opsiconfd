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

from opsiconfd.application.metrics import (
	get_nodes,
	get_workers,
	grafana_dashboard_config,
	grafana_search,
)
from opsiconfd.metrics.statistics import setup_metric_downsampling
from opsiconfd.redis import async_delete_recursively, async_redis_client

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	clean_redis,
	config,
	test_client,
)


async def _register_workers(conf: Config) -> tuple[dict[str, str | int], ...]:
	node_name = "testnode"
	workers: tuple[dict[str, str | int], ...] = (
		{"node_name": node_name, "pid": 121, "worker_num": 1},
		{"node_name": node_name, "pid": 122, "worker_num": 2},
		{"node_name": node_name, "pid": 123, "worker_num": 3},
	)
	redis = await async_redis_client()
	for worker in workers:
		redis_key = f"{conf.redis_key('state')}:workers:{node_name}:{worker['worker_num']}"
		await redis.hset(
			redis_key,
			key=None,
			value=None,
			mapping={"worker_pid": worker["pid"], "node_name": worker["node_name"], "worker_num": worker["worker_num"]},
		)
		await redis.expire(redis_key, 5)
	return workers


async def test_get_workers(config: Config) -> None:  # noqa: F811
	workers = await _register_workers(config)
	_workers = await get_workers()
	for worker in workers:
		found = False
		for _worker in _workers:
			if _worker["node_name"] == worker["node_name"] and _worker["worker_num"] == worker["worker_num"]:
				found = True
				break
		if not found:
			raise RuntimeError(f"Worker {worker} not found")


async def test_get_nodes(config: Config) -> None:  # noqa: F811
	workers = await _register_workers(config)
	nodes = await get_nodes()
	for worker in workers:
		assert worker["node_name"] in nodes


async def test_grafana_dashboard_config() -> None:
	conf = await grafana_dashboard_config()
	assert len(conf["panels"]) == 13


async def test_grafana_search(config: Config) -> None:  # noqa: F811
	workers = await _register_workers(config)
	res = await grafana_search()
	for worker in workers:
		assert f"Average CPU usage of worker {worker['worker_num']} on {worker['node_name']}" in res


async def create_ts_data(conf: Config, postfix: str, start: int, end: int, interval: int, value: float, delete: bool = True) -> None:
	redis_key = f"{conf.redis_key('stats')}:worker:avg_cpu_percent:{conf.node_name}:1{':' + postfix if postfix else ''}"
	if delete:
		await async_delete_recursively(f"{conf.redis_key('stats')}:worker:avg_cpu_percent")
		await asyncio.get_running_loop().run_in_executor(None, setup_metric_downsampling)

	# Do not use a pipeline here (will kill redis-server)
	redis = await async_redis_client()
	timestamp = start
	while timestamp <= end:
		# print(timestamp * 1000)
		cmd = (
			"TS.ADD",
			redis_key,
			timestamp * 1000,
			value,
			"RETENTION",
			7200000,
			"ON_DUPLICATE",
			"LAST",
			"LABELS",
			"node_name",
			conf.node_name,
			"worker_num",
			1,
		)
		await redis.execute_command(" ".join([str(x) for x in cmd]))  # type: ignore[no-untyped-call]
		timestamp += interval


# @pytest.mark.flaky(retries=1, delay=1)
async def test_grafana_query_start_end(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	utc_now = datetime.datetime.now(tz=datetime.timezone.utc)

	# Create some data
	start = int(utc_now.timestamp()) - 3600
	end = int(utc_now.timestamp())
	value = 10
	interval = 5
	interval_minute = 60
	await create_ts_data(config, "", start, end, interval, value)
	await create_ts_data(config, "minute", end - 23 * 3600, end, interval_minute, value, False)

	seconds = 300
	_to = utc_now
	_from = _to - datetime.timedelta(seconds=seconds)
	query = {
		"app": "dashboard",
		"range": {"from": _from.isoformat(), "to": _to.isoformat(), "raw": {"from": f"now-{seconds}s", "to": "now"}},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [
			{"type": "timeserie", "target": f"{config.redis_key('stats')}:worker:avg_cpu_percent:{config.node_name}:1", "refId": "A"}
		],
	}

	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()
	# print(data[0]["datapoints"])
	num_values = len(data[0]["datapoints"])
	expected_values = seconds / interval

	assert expected_values - 1 <= num_values <= expected_values + 1
	assert data[0]["datapoints"][0][1] >= (_from.timestamp() - interval) * 1000
	assert data[0]["datapoints"][-1][1] <= (_to.timestamp() + interval) * 1000
	correct_values = [dat for dat in data[0]["datapoints"] if dat[0] == value]
	assert len(correct_values) == num_values

	# Downsampling (minute)
	seconds = 10 * 3600
	_to = utc_now
	_from = _to - datetime.timedelta(seconds=seconds)
	query = {
		"app": "dashboard",
		"range": {"from": _from.isoformat(), "to": _to.isoformat(), "raw": {"from": f"now-{seconds}s", "to": "now"}},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [
			{"type": "timeserie", "target": f"{config.redis_key('stats')}:worker:avg_cpu_percent:{config.node_name}:1", "refId": "A"}
		],
	}

	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()
	# print(data[0]["datapoints"])
	num_values = len(data[0]["datapoints"])
	expected_values = seconds / interval_minute

	assert expected_values - 1 <= num_values <= expected_values + 1
	assert data[0]["datapoints"][0][1] >= (_from.timestamp() - interval_minute) * 1000
	assert data[0]["datapoints"][-1][1] <= (_to.timestamp() + interval_minute) * 1000
	correct_values = [dat for dat in data[0]["datapoints"] if dat[0] == value]
	assert len(correct_values) == num_values

	# minute, end one hour in the past
	seconds = 10 * 3600
	_to = utc_now - datetime.timedelta(seconds=3600)
	_from = _to - datetime.timedelta(seconds=seconds)
	query = {
		"app": "dashboard",
		"range": {"from": _from.isoformat(), "to": _to.isoformat(), "raw": {"from": f"now-{seconds}s", "to": "now"}},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [
			{"type": "timeserie", "target": f"{config.redis_key('stats')}:worker:avg_cpu_percent:{config.node_name}:1", "refId": "A"}
		],
	}

	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()
	# print(data[0]["datapoints"])
	num_values = len(data[0]["datapoints"])
	expected_values = seconds / interval_minute

	assert expected_values - 1 <= num_values <= expected_values + 1
	assert data[0]["datapoints"][0][1] >= (_from.timestamp() - interval_minute) * 1000
	assert data[0]["datapoints"][-1][1] <= (_to.timestamp() + interval_minute) * 1000
	correct_values = [dat for dat in data[0]["datapoints"] if dat[0] == value]
	assert len(correct_values) == num_values


async def test_grafana_query_interval_in_past(
	test_client: OpsiconfdTestClient,  # noqa: F811
	config: Config,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	utc_now = datetime.datetime.now(tz=datetime.timezone.utc)

	end = int(utc_now.timestamp())
	await create_ts_data(config, "minute", end - 23 * 3600, end, 60, 20)
	await create_ts_data(config, "hour", end - 35 * 3600, end, 3600, 40, False)

	# Interval (from -> to) is one hour and should use minutes
	# but 30h ago the minutes should be deleted so hours should be used
	# grafana seconds: seconds to go back in time (now-grafana seconds)
	grafana_seconds = 30 * 3600
	end = int(utc_now.timestamp()) - grafana_seconds
	seconds = 3600

	_to = datetime.datetime.fromtimestamp(end)
	_from = _to - datetime.timedelta(seconds=seconds)

	query = {
		"app": "dashboard",
		"range": {
			"from": _from.isoformat(),
			"to": _to.isoformat(),
			"raw": {"from": f"now-{grafana_seconds + seconds}s", "to": f"now-{grafana_seconds}s"},
		},
		"intervalMs": 500,
		"timezone": "utc",
		"targets": [
			{"type": "timeserie", "target": f"{config.redis_key('stats')}:worker:avg_cpu_percent:{config.node_name}:1", "refId": "A"}
		],
	}

	res = test_client.post("/metrics/grafana/query", json=query)
	assert res.status_code == 200
	data = res.json()

	assert data[0]["datapoints"] != []
	for dat in data[0]["datapoints"]:
		assert dat[0] == 40
