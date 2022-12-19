# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd redis utils
"""


from __future__ import annotations

import asyncio
import functools
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Callable, Generator
from uuid import uuid4

import redis
from redis import BusyLoadingError as RedisBusyLoadingError
from redis import ConnectionError as RedisConnectionError
from redis import asyncio as async_redis

from opsiconfd.config import config
from opsiconfd.utils import normalize_ip_address

redis_pool_lock = threading.Lock()
async_redis_pool_lock = asyncio.Lock()
redis_connection_pool: dict[str, redis.ConnectionPool] = {}
async_redis_connection_pool: dict[str, async_redis.ConnectionPool] = {}


def decode_redis_result(_obj: Any) -> Any:
	if isinstance(_obj, bytes):
		_obj = _obj.decode("utf8")
	elif isinstance(_obj, list):
		for idx in range(len(_obj)):  # pylint: disable=consider-using-enumerate
			_obj[idx] = decode_redis_result(_obj[idx])
	elif isinstance(_obj, dict):
		for (key, val) in _obj.items():
			_obj[decode_redis_result(key)] = decode_redis_result(val)
	elif isinstance(_obj, set):
		for val in _obj:
			_obj.remove(val)
			_obj.add(decode_redis_result(val))
	return _obj


def ip_address_to_redis_key(address: str) -> str:
	if ":" in address:
		# ipv6
		return normalize_ip_address(address, exploded=True).replace(":", ".")
	return address


def ip_address_from_redis_key(key: str) -> str:
	if key.count(".") > 3:
		# ipv6
		return key.replace(".", ":")
	return key


def retry_redis_call(func: Callable) -> Callable:
	@functools.wraps(func)
	def wrapper_retry(*args: Any, **kwargs: Any) -> Callable:  # pylint: disable=inconsistent-return-statements
		while True:
			try:  # pylint: disable=loop-try-except-usage
				return func(*args, **kwargs)  # pylint: disable=loop-invariant-statement
			except (  # pylint: disable=loop-invariant-statement
				RedisBusyLoadingError,
				RedisConnectionError,
			):
				time.sleep(2)  # pylint: disable=dotted-import-in-loop

	return wrapper_retry


def get_redis_connection(url: str, db: int = 0, timeout: int = 0, test_connection: bool = False) -> redis.StrictRedis:  # pylint: disable=invalid-name
	start = time.time()
	con_id = f"{url}/{db}"
	while True:
		try:  # pylint: disable=loop-try-except-usage
			new_pool = False
			with redis_pool_lock:  # pylint: disable=loop-global-usage
				if con_id not in redis_connection_pool:  # pylint: disable=loop-global-usage,loop-invariant-statement
					new_pool = True
					redis_connection_pool[con_id] = redis.ConnectionPool.from_url(url, db=db)  # pylint: disable=dotted-import-in-loop,loop-global-usage,loop-invariant-statement
			client = redis.StrictRedis(connection_pool=redis_connection_pool[con_id])  # pylint: disable=dotted-import-in-loop,loop-invariant-statement,loop-global-usage
			if new_pool or test_connection:
				client.ping()
			return client
		except (redis.exceptions.ConnectionError, redis.BusyLoadingError):  # pylint: disable=dotted-import-in-loop
			if timeout and time.time() - start >= timeout:  # pylint: disable=dotted-import-in-loop
				raise
			time.sleep(2)  # pylint: disable=dotted-import-in-loop


@contextmanager
def redis_client(timeout: int = 0, test_connection: bool = False) -> Generator[redis.StrictRedis, None, None]:
	con = get_redis_connection(url=config.redis_internal_url, timeout=timeout, test_connection=test_connection)
	try:
		yield con
	finally:
		con.close()


async def get_async_redis_connection(url: str, db: int = 0, timeout: int = 0, test_connection: bool = False) -> async_redis.StrictRedis:  # pylint: disable=invalid-name
	start = time.time()
	while True:
		try:  # pylint: disable=loop-try-except-usage
			con_id = f"{id(asyncio.get_running_loop())}/{url}/{db}"  # pylint: disable=dotted-import-in-loop
			new_pool = False
			async with async_redis_pool_lock:  # pylint: disable=loop-global-usage
				if con_id not in async_redis_connection_pool:  # pylint: disable=loop-global-usage
					new_pool = True
					async_redis_connection_pool[con_id] = async_redis.ConnectionPool.from_url(url, db=db)  # pylint: disable=dotted-import-in-loop,loop-global-usage
			# This will return a client (no Exception) even if connection is currently lost
			client: async_redis.StrictRedis = async_redis.StrictRedis(connection_pool=async_redis_connection_pool[con_id])  # pylint: disable=dotted-import-in-loop,loop-global-usage
			if new_pool or test_connection:
				await client.ping()
			return client
		except (RedisConnectionError, RedisBusyLoadingError):  # pylint: disable=loop-invariant-statement
			if timeout and time.time() - start >= timeout:  # pylint: disable=dotted-import-in-loop
				raise
			await asyncio.sleep(2)  # pylint: disable=dotted-import-in-loop


async def async_redis_client(timeout: int = 0, test_connection: bool = False) -> async_redis.StrictRedis:
	return await get_async_redis_connection(url=config.redis_internal_url, timeout=timeout, test_connection=test_connection)


@contextmanager
def redis_lock(lock_name: str, acquire_timeout: float = 10.0, lock_timeout: float | None = None) -> Generator[str, None, None]:
	conf = config
	identifier = str(uuid4())
	indentifier_b = identifier.encode("utf-8")
	redis_key = f"{conf.redis_key('locks')}:{lock_name}"
	end = time.time() + acquire_timeout
	with redis_client() as client:
		while True:  # pylint: disable=dotted-import-in-loop
			if client.setnx(redis_key, identifier):
				if lock_timeout:
					client.pexpire(redis_key, round(lock_timeout * 1000))  # milliseconds  # pylint: disable=loop-invariant-statement
				break
			if time.time() >= end:  # pylint: disable=dotted-import-in-loop
				raise TimeoutError(f"Failed to acquire {lock_name} lock in {acquire_timeout:0.2f} seconds")  # pylint: disable=loop-invariant-statement
			time.sleep(0.5)  # pylint: disable=dotted-import-in-loop

		yield identifier

		with client.pipeline(transaction=True) as pipe:
			while True:
				try:  # pylint: disable=loop-try-except-usage
					# Redis will only perform the transaction if the watched keys were not modified.
					pipe.watch(redis_key)
					if pipe.get(redis_key) == indentifier_b:
						# Release lock
						pipe.multi()
						pipe.delete(redis_key)
						pipe.execute()
					else:
						# Different identifier, not our lock
						pipe.unwatch()
					break
				except redis.exceptions.WatchError:  # pylint: disable=dotted-import-in-loop,loop-invariant-statement
					pass


@asynccontextmanager
async def async_redis_lock(lock_name: str, acquire_timeout: float = 10.0, lock_timeout: float | None = None) -> AsyncGenerator[str, None]:
	conf = config
	identifier = str(uuid4())
	identifier_b = identifier.encode("utf-8")
	redis_key = f"{conf.redis_key('locks')}:{lock_name}"
	end = time.time() + acquire_timeout
	client = await async_redis_client()

	while True:  # pylint: disable=dotted-import-in-loop
		if await client.setnx(redis_key, identifier):
			if lock_timeout:
				await client.pexpire(redis_key, round(lock_timeout * 1000))  # milliseconds  # pylint: disable=loop-invariant-statement
			break
		if time.time() >= end:  # pylint: disable=dotted-import-in-loop,
			raise TimeoutError(f"Failed to acquire {lock_name} lock in {acquire_timeout:0.2f} seconds")  # pylint: disable=loop-invariant-statement
		await asyncio.sleep(0.5)  # pylint: disable=dotted-import-in-loop
	yield identifier

	async with client.pipeline(transaction=True) as pipe:
		while True:
			try:  # pylint: disable=loop-try-except-usage
				# Redis will only perform the transaction if the watched keys were not modified.
				await pipe.watch(redis_key)
				if await pipe.get(redis_key) == identifier_b:
					# Release lock
					pipe.multi()
					pipe.delete(redis_key)
					await pipe.execute()
				else:
					# Different identifier, not our lock
					await pipe.unwatch()
				break
			except redis.exceptions.WatchError:  # pylint: disable=dotted-import-in-loop,loop-invariant-statement
				pass


async def async_get_redis_info(client: async_redis.StrictRedis) -> dict[str, Any]:  # pylint: disable=too-many-locals
	conf = config
	stats_keys = []
	session_keys = []
	log_keys = []
	rpc_keys = []
	misc_keys = []
	redis_keys = client.scan_iter(f"{conf.redis_key()}:*")

	async for key in redis_keys:
		key = key.decode("utf8")
		if key.startswith(f"{conf.redis_key('stats')}:rpc") or key.startswith(f"{conf.redis_key('stats')}:num_rpc"):
			rpc_keys.append(key)
		elif key.startswith(f"{conf.redis_key('stats')}"):
			stats_keys.append(key)
		elif key.startswith(conf.redis_key('session')):
			session_keys.append(key)
		elif key.startswith(conf.redis_key('log')):
			log_keys.append(key)
		else:
			misc_keys.append(key)

	stats_memory = 0
	for key in stats_keys:
		stats_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0  # type: ignore[no-untyped-call]

	sessions_memory = 0
	for key in session_keys:
		sessions_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0  # type: ignore[no-untyped-call]

	logs_memory = 0
	log_records = 0
	for key in log_keys:
		logs_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0  # type: ignore[no-untyped-call]
		log_records += (await client.execute_command(f"XLEN {key}")) or 0  # type: ignore[no-untyped-call]

	rpc_memory = 0
	for key in rpc_keys:
		rpc_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0  # type: ignore[no-untyped-call]

	misc_memory = 0
	for key in misc_keys:
		misc_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0  # type: ignore[no-untyped-call]

	redis_info = decode_redis_result(await client.execute_command("INFO"))  # type: ignore[no-untyped-call]
	redis_info["key_info"] = {
		"stats": {"count": len(stats_keys), "memory": stats_memory},
		"sessions": {"count": len(session_keys), "memory": sessions_memory},
		"logs": {"count": len(log_keys), "memory": logs_memory, "records": log_records},
		"rpc": {"count": len(rpc_keys), "memory": rpc_memory},
		"misc": {"count": len(misc_keys), "memory": misc_memory},
	}
	return redis_info
