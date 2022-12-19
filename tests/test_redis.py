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

import pytest

from opsiconfd.redis import (
	async_redis_client,
	async_redis_connection_pool,
	async_redis_lock,
	redis_client,
	redis_connection_pool,
	redis_lock,
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
	for _ in range(num_connections):  # pylint: disable=use-list-copy
		connections.append(await pool.get_connection("_"))  # type: ignore[no-untyped-call]
	assert len(connections) == num_connections
	assert len(pool._in_use_connections) == num_connections  # type: ignore[attr-defined]  # pylint: disable=protected-access

	await asyncio.gather(*[pool.release(con) for con in connections])
	assert len(pool._in_use_connections) == 0  # type: ignore[attr-defined]  # pylint: disable=protected-access


@pytest.mark.asyncio
async def test_async_redis_pipeline(config: Config) -> None:  # pylint: disable=redefined-outer-name
	redis = await async_redis_client()
	async with redis.pipeline() as pipe:
		pipe.scan_iter(f"{config.redis_key()}:*")
		await pipe.execute()


def test_sync_redis_pool() -> None:
	num_connections = 1000
	with redis_client() as redis:
		pool = list(redis_connection_pool.values())[0]

	for _ in range(num_connections):
		with redis_client() as redis:
			redis.get("opsiconfd")

	assert len(pool._in_use_connections) == 0  # type: ignore[attr-defined]  # pylint: disable=protected-access

	connections = []
	for _ in range(num_connections):  # pylint: disable=use-list-copy
		connections.append(pool.get_connection("_"))
	assert len(connections) == num_connections
	assert len(pool._in_use_connections) == num_connections  # type: ignore[attr-defined]  # pylint: disable=protected-access

	for con in connections:
		pool.release(con)
	assert len(pool._in_use_connections) == 0  # type: ignore[attr-defined]  # pylint: disable=protected-access


def test_redis_lock() -> None:
	with redis_lock("test-lock", acquire_timeout=1.0):
		with pytest.raises(TimeoutError):
			with redis_lock("test-lock", acquire_timeout=2.0):
				time.sleep(3.0)

	with redis_lock("test-lock", acquire_timeout=1.0, lock_timeout=2.0):
		with redis_lock("test-lock", acquire_timeout=3.0):
			time.sleep(4.0)


@pytest.mark.asyncio
async def test_async_redis_lock() -> None:
	async with async_redis_lock("test-lock", acquire_timeout=1.0):
		with pytest.raises(TimeoutError):
			async with async_redis_lock("test-lock", acquire_timeout=2.0):
				time.sleep(3.0)

	async with async_redis_lock("test-lock", acquire_timeout=1.0, lock_timeout=2.0):
		async with async_redis_lock("test-lock", acquire_timeout=3.0):
			time.sleep(4.0)
