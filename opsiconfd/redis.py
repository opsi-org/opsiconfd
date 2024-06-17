# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd redis utils
"""

from __future__ import annotations

import asyncio
import base64
import functools
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, AsyncGenerator, Callable, Generator, Iterable
from uuid import uuid4

from opsicommon.utils import compare_versions
from redis import BusyLoadingError, Connection, ConnectionPool, Redis, ResponseError, WatchError
from redis import ConnectionError as RedisConnectionError
from redis.asyncio import Connection as AsyncConnection
from redis.asyncio import ConnectionPool as AsyncConnectionPool
from redis.asyncio import Redis as AsyncRedis
from redis.asyncio.connection import AbstractConnection

from opsiconfd.config import REDIS_CONECTION_TIMEOUT, config
from opsiconfd.utils import normalize_ip_address

redis_pool_lock = threading.Lock()
async_redis_pool_lock = asyncio.Lock()
redis_connection_pool: dict[str, ConnectionPool] = {}
async_redis_connection_pool: dict[str, AsyncConnectionPool] = {}


def repr_pieces(self: Connection | AsyncConnection) -> list[tuple[str, str | int]]:
	pieces: list[tuple[str, str | int]] = [("host", self.host), ("port", self.port), ("db", self.db), ("id", id(self))]
	if self.client_name:
		pieces.append(("client_name", self.client_name))
	return pieces


def __con_del__(self: AbstractConnection) -> None:
	try:
		self._close()  # type: ignore[attr-defined]
	except RuntimeError:
		pass


AsyncConnection.repr_pieces = repr_pieces  # type: ignore[method-assign]
Connection.repr_pieces = repr_pieces  # type: ignore[method-assign]
AbstractConnection.__del__ = __con_del__  # type: ignore[method-assign,attr-defined]


@lru_cache
def redis_supports_xtrim_minid() -> bool:
	return compare_versions(get_redis_version(), ">=", "6.2")


@lru_cache
def get_redis_version() -> str:
	client = redis_client()
	return client.info("server")["redis_version"]


def get_redis_connections() -> list[Connection | AsyncConnection]:
	connections = []
	for spool in redis_connection_pool.values():
		connections.extend(spool._in_use_connections)  # type: ignore[attr-defined]
	for apool in async_redis_connection_pool.values():
		connections.extend(apool._in_use_connections)  # type: ignore[attr-defined]
	return connections


async def _async_pool_disconnect_connections(inuse_connections: bool = False) -> None:
	async with async_redis_pool_lock:
		for pool in async_redis_connection_pool.values():
			await pool.disconnect(inuse_connections)


def _sync_pool_disconnect_connections(inuse_connections: bool = False) -> None:
	with redis_pool_lock:
		for pool in redis_connection_pool.values():
			pool.disconnect(inuse_connections)


async def pool_disconnect_connections(inuse_connections: bool = False) -> None:
	await _async_pool_disconnect_connections(inuse_connections)
	asyncio.get_running_loop().run_in_executor(None, _sync_pool_disconnect_connections, inuse_connections)


def decode_redis_result(_obj: Any) -> Any:
	if isinstance(_obj, bytes):
		_obj = _obj.decode("utf8")
	if isinstance(_obj, list):
		_obj = [decode_redis_result(val) for val in _obj]
	elif isinstance(_obj, dict):
		_obj = {decode_redis_result(key): decode_redis_result(val) for key, val in _obj.items()}
	elif isinstance(_obj, set):
		_obj = {decode_redis_result(val) for val in _obj}
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
	def wrapper_retry(*args: Any, **kwargs: Any) -> Callable:
		while True:
			try:
				return func(*args, **kwargs)
			except (
				BusyLoadingError,
				RedisConnectionError,
			):
				time.sleep(2)

	return wrapper_retry


def get_redis_connection(
	url: str,
	db: int = 0,
	timeout: int = 0,
	test_connection: bool = False,
) -> Redis:
	start = time.time()
	con_id = f"{url}/{db}"
	while True:
		try:
			new_pool = False
			with redis_pool_lock:
				if con_id not in redis_connection_pool:
					new_pool = True
					redis_connection_pool[con_id] = ConnectionPool.from_url(url, db=db)
			client = Redis(connection_pool=redis_connection_pool[con_id])
			if new_pool or test_connection:
				client.ping()
			return client
		except (RedisConnectionError, BusyLoadingError):
			if timeout and time.time() - start >= timeout:
				raise
			time.sleep(2)


def redis_client(timeout: int = 0, test_connection: bool = False) -> Redis:
	return get_redis_connection(url=config.redis_internal_url, timeout=timeout, test_connection=test_connection)


async def get_async_redis_connection(
	url: str,
	db: int = 0,
	timeout: int = 0,
	test_connection: bool = False,
) -> AsyncRedis:
	start = time.time()
	while True:
		try:
			con_id = f"{id(asyncio.get_running_loop())}/{url}/{db}"
			new_pool = False
			async with async_redis_pool_lock:
				if con_id not in async_redis_connection_pool:
					new_pool = True
					async_redis_connection_pool[con_id] = AsyncConnectionPool.from_url(url, db=db)
			# This will return a client (no Exception) even if connection is currently lost
			client = AsyncRedis(connection_pool=async_redis_connection_pool[con_id])
			if new_pool or test_connection:
				await client.ping()
			return client
		except (RedisConnectionError, BusyLoadingError):
			if timeout and time.time() - start >= timeout:
				raise
			await asyncio.sleep(2)


async def async_redis_client(timeout: int = 0, test_connection: bool = False) -> AsyncRedis:
	return await get_async_redis_connection(url=config.redis_internal_url, timeout=timeout, test_connection=test_connection)


@dataclass(frozen=True, slots=True)
class DumpedKey:
	name: str
	value: bytes
	expires: int | None = None  # absolute unix timestamp in milliseconds or None if not expires

	@classmethod
	def from_dict(cls, data: dict[str, str | bytes | int | None]) -> DumpedKey:
		if isinstance(data["value"], str):
			return DumpedKey(name=data["name"], value=base64.b64decode(data["value"]), expires=data["expires"])  # type: ignore[arg-type]
		return DumpedKey(**data)  # type: ignore[arg-type]


def dump(redis_key: str, *, excludes: Iterable[str] | None = None) -> Generator[DumpedKey, None, None]:
	excludes = excludes or []
	client = redis_client()
	for key in client.scan_iter(f"{redis_key}:*"):
		assert isinstance(key, bytes)
		key = key.decode("utf-8")

		exclude_key = False
		for exclude in excludes:
			if key == exclude or key.startswith(f"{exclude}:"):
				exclude_key = True
				break
		if exclude_key:
			continue

		now = int(time.time() * 1000)
		value = client.dump(key)
		pttl = client.pttl(key)
		expires = None
		if pttl >= 0:
			expires = now + pttl
		assert isinstance(value, bytes)
		yield DumpedKey(key, value, expires)


def restore(dumped_keys: Iterable[DumpedKey]) -> None:
	for dumped_key in dumped_keys:
		redis_client().restore(
			name=dumped_key.name,
			ttl=0 if dumped_key.expires is None else dumped_key.expires,
			value=dumped_key.value,
			absttl=True,
			replace=True,
		)


def delete_recursively(redis_key: str, *, piped: bool = True, excludes: Iterable[str] | None = None) -> None:
	excludes = excludes or []

	client = redis_client()
	delete_keys = []
	for key in client.scan_iter(f"{redis_key}:*"):
		assert isinstance(key, bytes)
		key = key.decode("utf-8")

		exclude_key = False
		for exclude in excludes:
			if key == exclude or key.startswith(f"{exclude}:"):
				exclude_key = True
				break
		if exclude_key:
			continue

		if piped:
			delete_keys.append(key)
		else:
			client.unlink(key)

	if piped:
		with client.pipeline() as pipe:
			for key in delete_keys:
				pipe.unlink(key)
			pipe.unlink(redis_key)
			pipe.execute()
	else:
		client.unlink(redis_key)


async def async_delete_recursively(redis_key: str, piped: bool = True) -> None:
	client = await async_redis_client()
	delete_keys = []
	async for key in client.scan_iter(f"{redis_key}:*"):
		if piped:
			delete_keys.append(key)
		else:
			await client.unlink(key)

	if piped:
		async with client.pipeline() as pipe:
			for key in delete_keys:
				pipe.unlink(key)  # type: ignore[attr-defined]
			pipe.unlink(redis_key)  # type: ignore[attr-defined]
			await pipe.execute()  # type: ignore[attr-defined]
	else:
		await client.unlink(redis_key)


@contextmanager
def redis_lock(lock_name: str, acquire_timeout: float = 10.0, lock_timeout: float | None = None) -> Generator[str, None, None]:
	conf = config
	identifier = str(uuid4())
	indentifier_b = identifier.encode("utf-8")
	redis_key = f"{conf.redis_key('locks')}:{lock_name}"
	end = time.time() + acquire_timeout
	pxt = round(lock_timeout) * 1000 if lock_timeout else None
	client = redis_client()
	while True:
		# PXAT timestamp-milliseconds -- Set the specified Unix time at which the key will expire, in milliseconds.
		if client.set(redis_key, identifier, nx=True, px=pxt):
			break
		if time.time() >= end:
			raise TimeoutError(f"Failed to acquire {lock_name} lock in {acquire_timeout:0.2f} seconds")
		time.sleep(0.5)
	try:
		yield identifier
	finally:
		with client.pipeline(transaction=True) as pipe:
			while True:
				try:
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
				except WatchError:
					pass


@asynccontextmanager
async def async_redis_lock(lock_name: str, acquire_timeout: float = 10.0, lock_timeout: float | None = None) -> AsyncGenerator[str, None]:
	conf = config
	identifier = str(uuid4())
	identifier_b = identifier.encode("utf-8")
	redis_key = f"{conf.redis_key('locks')}:{lock_name}"
	end = time.time() + acquire_timeout
	pxt = round(lock_timeout) * 1000 if lock_timeout else None
	client = await async_redis_client()

	while True:
		# PXAT timestamp-milliseconds -- Set the specified Unix time at which the key will expire, in milliseconds.
		if await client.set(redis_key, identifier, nx=True, px=pxt):
			break
		if time.time() >= end:
			raise TimeoutError(f"Failed to acquire {lock_name} lock in {acquire_timeout:0.2f} seconds")
		await asyncio.sleep(0.5)

	try:
		yield identifier
	finally:
		async with client.pipeline(transaction=True) as pipe:
			while True:
				try:
					# Redis will only perform the transaction if the watched keys were not modified.
					await pipe.watch(redis_key)  # type: ignore[attr-defined]
					if await pipe.get(redis_key) == identifier_b:  # type: ignore[attr-defined]
						# Release lock
						pipe.multi()  # type: ignore[attr-defined]
						pipe.delete(redis_key)  # type: ignore[attr-defined]
						await pipe.execute()  # type: ignore[attr-defined]
					else:
						# Different identifier, not our lock
						await pipe.unwatch()  # type: ignore[attr-defined]
					break
				except WatchError:
					pass


async def async_get_redis_info(client: AsyncRedis) -> dict[str, Any]:
	conf = config

	key_info: dict[str, dict[str, list | int]] = {
		"rpc": {
			"keys": [],
			"memory": 0,
			"entries": 0,
			"prefixes": [f"{conf.redis_key('stats')}:rpc", f"{conf.redis_key('stats')}:num_rpc"],
		},
		"stats": {"keys": [], "memory": 0, "entries": 0, "prefixes": [conf.redis_key("stats")]},
		"session": {"keys": [], "memory": 0, "entries": 0, "prefixes": [conf.redis_key("session")]},
		"log": {"keys": [], "memory": 0, "entries": 0, "prefixes": [conf.redis_key("log")]},
		"state": {"keys": [], "memory": 0, "entries": 0, "prefixes": [conf.redis_key("state")]},
		"messagebus": {"keys": [], "memory": 0, "entries": 0, "prefixes": [conf.redis_key("messagebus")]},
		"misc": {"keys": [], "memory": 0, "entries": 0, "prefixes": []},
	}

	async for key in client.scan_iter(f"{conf.redis_key()}:*"):
		key = key.decode("utf8")
		matched_key_type = ""
		for key_type, info in key_info.items():
			for prefix in info["prefixes"]:  # type: ignore[union-attr]
				if key.startswith(prefix):
					matched_key_type = key_type
					break
		matched_key_type = matched_key_type or "misc"
		key_info[matched_key_type]["keys"].append(key)  # type: ignore[union-attr]
		try:
			command = f"MEMORY USAGE {key}"
			key_info[matched_key_type]["memory"] += (  # type: ignore[union-attr,operator]
				await client.execute_command(command)  # type: ignore[no-untyped-call]
			) or 0
		except ResponseError as err:
			from opsiconfd.logging import logger

			logger.error("Redis command %r failed: %s", command, err, exc_info=True)
		try:
			key_info[matched_key_type]["entries"] += (  # type: ignore[union-attr,operator]
				await client.execute_command(f"XLEN {key}")  # type: ignore[no-untyped-call]
			) or 0
		except ResponseError:
			# Wrong key type
			pass

	def decode_value(key: str, value: Any) -> Any:
		if isinstance(value, dict):
			return {k: decode_value(k, v) for k, v in value.items()}
		if not isinstance(value, str):
			return value
		if key == "ver" or "version" in key:
			# Do not convert to number
			return value
		if "=" in value:
			return decode_value(key, dict(v.split("=") for v in value.split(",")))
		try:
			if "." in value:
				return float(value)
			else:
				return int(value)
		except ValueError:
			pass
		return value

	redis_info: dict[str, dict[str, Any]] = {}
	section = None
	for line in decode_redis_result(await client.execute_command("INFO ALL")).split("\n"):  # type: ignore[no-untyped-call]
		line = line.strip()
		if not line:
			continue
		if line.startswith("#"):
			section = line[1:].strip().lower()
			redis_info[section] = {}
			continue
		assert section
		key, value = line.split(":", 1)
		value = decode_value(key, value)
		redis_info[section][key] = value

	redis_info["key_info"] = {
		key_type: {"keys": len(info["keys"]), "memory": info["memory"], "entries": info["entries"]}  # type: ignore[arg-type]
		for key_type, info in key_info.items()
	}
	return redis_info


def delete_locks() -> None:
	redis_client(timeout=REDIS_CONECTION_TIMEOUT, test_connection=True)
	delete_recursively(config.redis_key("locks"))
