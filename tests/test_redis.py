# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
redis tests
"""

import asyncio
import pytest

from opsiconfd.utils import async_redis_client, async_redis_connection_pool, redis_client, redis_connection_pool


@pytest.mark.asyncio
async def test_async_redis_pool():
	num_connections = 1000
	redis = await async_redis_client()
	pool = list(async_redis_connection_pool.values())[0]
	coroutines = []
	for _ in range(num_connections):
		redis = await async_redis_client()
		coroutines.append(redis.get("opsiconfd"))

	assert len(await asyncio.gather(*coroutines)) == num_connections
	assert len(pool._in_use_connections) == 0  # pylint: disable=protected-access

	connections = []
	for _ in range(num_connections):
		connections.append(await pool.get_connection("_"))
	assert len(connections) == num_connections
	assert len(pool._in_use_connections) == num_connections  # pylint: disable=protected-access

	await asyncio.gather(*[pool.release(con) for con in connections])
	assert len(pool._in_use_connections) == 0  # pylint: disable=protected-access


@pytest.mark.asyncio
async def test_async_redis_pipeline():
	redis = await async_redis_client()
	async with redis.pipeline() as pipe:
		pipe.scan_iter("opsiconfd:*")
		await pipe.execute()


def test_sync_redis_pool():
	num_connections = 1000
	with redis_client() as redis:
		pool = list(redis_connection_pool.values())[0]

	for _ in range(num_connections):
		with redis_client() as redis:
			redis.get("opsiconfd")

	assert len(pool._in_use_connections) == 0  # pylint: disable=protected-access

	connections = []
	for _ in range(num_connections):
		connections.append(pool.get_connection("_"))
	assert len(connections) == num_connections
	assert len(pool._in_use_connections) == num_connections  # pylint: disable=protected-access

	for con in connections:
		pool.release(con)
	assert len(pool._in_use_connections) == 0  # pylint: disable=protected-access
