# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
redis tests
"""

import asyncio
import time
from random import randbytes
from unittest.mock import patch

import pytest

from opsiconfd.metrics.collector import ManagerMetricsCollector
from opsiconfd.metrics.registry import MetricsRegistry, NodeMetric
from opsiconfd.metrics.statistics import setup_metric_downsampling
from opsiconfd.redis import (
	async_delete_recursively,
	async_redis,
	async_redis_client,
	async_redis_connection_pool,
	async_redis_lock,
	delete_recursively,
	dump,
	redis_client,
	redis_connection_pool,
	redis_lock,
	restore,
)

from .utils import Config, config  # pylint: disable=unused-import


@pytest.mark.asyncio
async def test_async_redis_pool() -> None:
	num_connections = 1000
	redis = await async_redis_client()
	pool = list(async_redis_connection_pool.values())[0]
	coroutines = []
	for _ in range(num_connections):
		redis = await async_redis_client()
		coroutines.append(redis.get("opsiconfd"))

	assert len(await asyncio.gather(*coroutines)) == num_connections
	assert len(pool._in_use_connections) == 0  # type: ignore[attr-defined]  # pylint: disable=protected-access

	connections = []
	for _ in range(num_connections):
		connections.append(await pool.get_connection("_"))  # type: ignore[no-untyped-call]
	assert len(connections) == num_connections
	assert len(pool._in_use_connections) == num_connections  # type: ignore[attr-defined]  # pylint: disable=protected-access

	await asyncio.gather(*[pool.release(con) for con in connections])
	assert len(pool._in_use_connections) == 0  # type: ignore[attr-defined]  # pylint: disable=protected-access


@pytest.mark.asyncio
async def test_async_redis_pipeline(config: Config) -> None:  # pylint: disable=redefined-outer-name
	redis = await async_redis_client()
	async with redis.pipeline() as pipe:
		pipe.scan_iter(f"{config.redis_key()}:*")  # type: ignore[attr-defined]
		await pipe.execute()  # type: ignore[attr-defined]


def test_sync_redis_pool() -> None:
	num_connections = 1000
	with redis_client() as redis:
		pool = list(redis_connection_pool.values())[0]

	for _ in range(num_connections):
		with redis_client() as redis:
			redis.get("opsiconfd")

	assert len(pool._in_use_connections) == 0  # type: ignore[attr-defined]  # pylint: disable=protected-access

	connections = []
	for _ in range(num_connections):
		connections.append(pool.get_connection("_"))
	assert len(connections) == num_connections
	assert len(pool._in_use_connections) == num_connections  # type: ignore[attr-defined]  # pylint: disable=protected-access

	for con in connections:
		pool.release(con)
	assert len(pool._in_use_connections) == 0  # type: ignore[attr-defined]  # pylint: disable=protected-access


@pytest.mark.asyncio
@pytest.mark.parametrize(
	"piped",
	(False, True),
)
async def test_async_delete_recursively(config: Config, piped: bool) -> None:  # pylint: disable=redefined-outer-name
	client = await async_redis_client()
	base_key = config.redis_key("delete_recursively")
	for idx in range(10):
		for idx2 in range(5):
			await client.set(f"{base_key}:{idx}:{idx2}", b"test")

	keys = [k async for k in client.scan_iter(f"{base_key}:*")]
	assert len(keys) == 50

	await async_delete_recursively(base_key, piped=piped)

	keys = [k async for k in client.scan_iter(f"{base_key}:*")]
	assert len(keys) == 0


@pytest.mark.parametrize(
	"piped",
	(False, True),
)
def test_delete_recursively(config: Config, piped: bool) -> None:  # pylint: disable=redefined-outer-name
	with redis_client() as client:
		base_key = config.redis_key("delete_recursively")
		for idx in range(10):
			for idx2 in range(5):
				client.set(f"{base_key}:{idx}:{idx2}", b"test")

		keys = list(client.scan_iter(f"{base_key}:*"))
		assert len(keys) == 50

		delete_recursively(base_key, piped=piped)

		keys = list(client.scan_iter(f"{base_key}:*"))
		assert len(keys) == 0


def test_redis_lock(config: Config) -> None:  # pylint: disable=redefined-outer-name
	lock_name = "test-lock"
	redis_key = f"{config.redis_key('locks')}:{lock_name}"

	with redis_client() as client:
		assert not client.get(redis_key)

		with redis_lock(lock_name, acquire_timeout=1.0):
			# Lock acquired
			assert client.get(redis_key)
			with pytest.raises(TimeoutError):
				# Lock cannot be acquired twice => TimeoutError
				with redis_lock(lock_name, acquire_timeout=2.0):
					time.sleep(3.0)

		assert not client.get(redis_key)

		with redis_lock(lock_name, acquire_timeout=1.0, lock_timeout=2.0):
			# Lock acquired, lock will be auto removed from redis after 2 seconds
			time.sleep(3.0)
			assert not client.get(redis_key)
			with redis_lock(lock_name, acquire_timeout=1.0):
				time.sleep(1.0)

		assert not client.get(redis_key)


@pytest.mark.asyncio
async def test_async_redis_lock(config: Config) -> None:  # pylint: disable=redefined-outer-name
	lock_name = "test-lock"
	redis_key = f"{config.redis_key('locks')}:{lock_name}"
	client = await async_redis_client()

	assert not await client.get(redis_key)

	async with async_redis_lock("test-lock", acquire_timeout=1.0):
		# Lock acquired
		assert await client.get(redis_key)
		with pytest.raises(TimeoutError):
			# Lock cannot be acquired twice => TimeoutError
			async with async_redis_lock("test-lock", acquire_timeout=2.0):
				await asyncio.sleep(3.0)

	assert not await client.get(redis_key)

	async with async_redis_lock("test-lock", acquire_timeout=1.0, lock_timeout=2.0):
		# Lock acquired, lock will be auto removed from redis after 2 seconds
		await asyncio.sleep(3.0)
		assert not await client.get(redis_key)
		async with async_redis_lock("test-lock", acquire_timeout=3.0):
			await asyncio.sleep(1.0)

	assert not await client.get(redis_key)


@pytest.mark.asyncio
async def test_dump_restore(config: Config) -> None:  # pylint: disable=redefined-outer-name,too-many-locals,too-many-statements
	base_key = config.redis_key("dump_recursively")
	metric = NodeMetric(
		id="opsiconfd:pytest:metric",
		name="opsiconfd pytest metric",
		retention=24 * 3600 * 1000,
		grafana_config=None,
		downsampling=[["minute", 2 * 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"]],  # keep minutes longer
	)
	metric.set_redis_prefix(f"{base_key}:stats")
	metrics_registry = MetricsRegistry()
	metrics_registry.register(metric)
	setup_metric_downsampling()

	current_timestamp = 0

	def _get_timestamp(self: ManagerMetricsCollector) -> int:  # pylint:disable=unused-argument
		# Return unix timestamp (UTC) in millis
		return current_timestamp

	collector = ManagerMetricsCollector()
	with patch("opsiconfd.metrics.collector.ManagerMetricsCollector._get_timestamp", _get_timestamp):
		now_ts = int(time.time() * 1000)
		num_values = 7200
		start_ts = now_ts - num_values * 1000
		for val_num in range(num_values):
			current_timestamp = start_ts + val_num * 1000
			await collector.add_value(metric_id=metric.id, value=10.0)
			await collector._write_values_to_redis()  # pylint:disable=protected-access

	await asyncio.sleep(1)
	rand = randbytes(3000)
	num1 = 30
	num2 = 30

	client = await async_redis_client()

	async def check_time_series(client: async_redis.StrictRedis) -> None:
		num_found = 0
		async for key_b in client.scan_iter(f"{base_key}:stats:*"):
			num_found += 1
			assert isinstance(key_b, bytes)
			key = key_b.decode("utf-8")
			res = await client.execute_command("TS.INFO", key)  # type: ignore[no-untyped-call]
			info = {k.decode("utf-8"): v for k, v in dict(zip(res[::2], res[1::2])).items()}
			# print(key, info)

			assert info["firstTimestamp"]
			if not key.endswith((":minute", ":hour")):
				assert len(info["rules"]) == 2
				for rule in info["rules"]:
					assert rule[0] in (f"{key}:minute".encode("utf-8"), f"{key}:hour".encode("utf-8"))

			cmd = ("TS.RANGE", key, start_ts, now_ts, "AGGREGATION", "avg", 1000)
			# print(cmd)
			vals = await client.execute_command(*cmd)  # type: ignore[no-untyped-call]
			# print(len(vals))
			if key.endswith(":hour"):
				assert len(vals) == 1
			elif key.endswith(":minute"):
				assert len(vals) == 119
			else:
				assert len(vals) == 7200
			assert vals[0][1] == b"10"
			assert vals[-1][1] == b"10"
		assert num_found == 3

	await check_time_series(client)

	for idx in range(num1):
		for idx2 in range(num2):
			ex = None if idx % 2 else 30
			await client.set(f"{base_key}:{idx}:{idx2}", rand, ex=ex)

	dumped_keys = list(dump(base_key, excludes=[f"{base_key}:1", f"{base_key}:2"]))
	assert len(dumped_keys) == (num1 - 2) * num2 + 3

	dumped_keys = list(dump(base_key))
	assert len(dumped_keys) == num1 * num2 + 3

	delete_recursively(base_key)

	restore(dumped_keys)
	setup_metric_downsampling()

	dumped_keys2 = list(dump(base_key))

	dumped_keys2.sort(key=lambda dk: dk.name)
	dumped_keys.sort(key=lambda dk: dk.name)
	assert len(dumped_keys2) == len(dumped_keys)
	for idx in range(len(dumped_keys)):  # pylint: disable=consider-using-enumerate
		assert dumped_keys2[idx].name == dumped_keys[idx].name
		assert dumped_keys2[idx].value == dumped_keys[idx].value
		if dumped_keys2[idx].expires is None:
			assert dumped_keys[idx].expires is None
		else:
			assert abs((dumped_keys2[idx].expires or 0) - (dumped_keys[idx].expires or 0)) < 3000

	await check_time_series(client)
