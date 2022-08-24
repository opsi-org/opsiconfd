# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
utils
"""

import asyncio
import codecs
import datetime
import functools
import ipaddress
import os
import random
import string
import threading
import time
import warnings
from contextlib import contextmanager
from socket import AF_INET, AF_INET6
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, Optional

with warnings.catch_warnings():
	# Ignore warning 'distutils Version classes are deprecated. Use packaging.version instead.'
	# aioredis/connection.py
	warnings.simplefilter("ignore")
	import aioredis

import psutil
import redis
from fastapi import APIRouter, FastAPI
from opsicommon.logging.logging import OPSILogger  # type: ignore[import]
from starlette.routing import Route

logger: OPSILogger | None = None  # pylint: disable=invalid-name
config = None  # pylint: disable=invalid-name
if TYPE_CHECKING:
	from config import Config  # type: ignore[import]
	config: "Config" | None = None  # type: ignore[no-redef]  # pylint: disable=invalid-name

redis_pool_lock = threading.Lock()
aioredis_pool_lock = asyncio.Lock()
redis_connection_pool = {}
aioredis_connection_pool = {}


def get_logger() -> OPSILogger:
	global logger  # pylint: disable=global-statement, invalid-name, global-variable-not-assigned
	if not logger:
		from .logging import (  # pylint: disable=import-outside-toplevel, redefined-outer-name
			logger,
		)
	return logger


def get_config() -> "Config":
	global config  # pylint: disable=global-statement, invalid-name, global-variable-not-assigned
	if not config:
		from .config import (  # type: ignore[misc]  # pylint: disable=import-outside-toplevel, redefined-outer-name
			config,
		)
	return config


class Singleton(type):
	_instances: Dict[type, type] = {}

	def __call__(cls: "Singleton", *args: Any, **kwargs: Any) -> type:
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


def utc_time_timestamp() -> float:
	return datetime.datetime.utcnow().timestamp()


def running_in_docker() -> bool:
	with codecs.open("/proc/self/cgroup", "r", "utf-8") as file:
		for line in file.readlines():
			if line.split(":")[2].startswith("/docker/"):
				return True
	return False


def is_opsiconfd(proc: psutil.Process) -> bool:
	return proc.name() == "opsiconfd" or (
		proc.name() in ("python", "python3") and ("opsiconfd" in proc.cmdline() or "opsiconfd.__main__" in " ".join(proc.cmdline()))
	)


def is_manager(proc: psutil.Process) -> bool:
	manager = False
	if is_opsiconfd(proc):
		manager = True
		for arg in proc.cmdline():
			if "multiprocessing" in arg or "log-viewer" in arg:
				manager = False
				break
	return manager


def get_manager_pid(ignore_self: bool = False, ignore_parents: bool = False) -> Optional[int]:
	manager_pid = None
	ignore_pids = []  # pylint: disable=use-tuple-over-list
	if ignore_self:
		our_pid = os.getpid()
		our_proc = psutil.Process(our_pid)
		ignore_pids += [our_pid]
		ignore_pids += [p.pid for p in our_proc.children(recursive=True)]
	if ignore_parents:
		ignore_pids += [p.pid for p in our_proc.parents()]

	for proc in psutil.process_iter():  # pylint: disable=dotted-import-in-loop
		if proc.pid in ignore_pids or proc.status() == psutil.STATUS_ZOMBIE:  # pylint: disable=dotted-import-in-loop
			continue
		if is_manager(proc) and (not manager_pid or proc.pid > manager_pid):
			# Do not return, prefer higher pids
			manager_pid = proc.pid

	return manager_pid


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


def normalize_ip_address(address: str, exploded: bool = False) -> str:
	ip_address = ipaddress.ip_address(address)
	if isinstance(ip_address, ipaddress.IPv6Address) and ip_address.ipv4_mapped:
		ip_address = ip_address.ipv4_mapped
	if exploded:
		return ip_address.exploded
	return ip_address.compressed


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


def get_ip_addresses() -> Generator[Dict[str, Any], None, None]:
	for interface, snics in psutil.net_if_addrs().items():  # pylint: disable=dotted-import-in-loop
		for snic in snics:
			family = None
			if snic.family == AF_INET:
				family = "ipv4"
			elif snic.family == AF_INET6:
				family = "ipv6"
			else:
				continue

			ip_address = None
			try:  # pylint: disable=loop-try-except-usage
				ip_address = ipaddress.ip_address(snic.address.split("%")[0])  # pylint: disable=dotted-import-in-loop
			except ValueError:
				if logger:  # pylint: disable=loop-global-usage
					logger.warning("Unrecognised ip address: %r", snic.address)  # pylint: disable=loop-global-usage

			yield {"family": family, "interface": interface, "address": snic.address, "ip_address": ip_address}


def get_random_string(length: int) -> str:
	letters = string.ascii_letters
	result_str = "".join(random.choice(letters) for i in range(length))
	return result_str


def retry_redis_call(func: Callable) -> Callable:
	@functools.wraps(func)
	def wrapper_retry(*args: Any, **kwargs: Any) -> Callable:  # pylint: disable=inconsistent-return-statements
		while True:
			try:  # pylint: disable=loop-try-except-usage
				return func(*args, **kwargs)  # pylint: disable=loop-invariant-statement
			except (  # pylint: disable=loop-invariant-statement
				aioredis.BusyLoadingError,  # pylint: disable=dotted-import-in-loop
				redis.exceptions.BusyLoadingError,  # pylint: disable=dotted-import-in-loop
				aioredis.ConnectionError,  # pylint: disable=dotted-import-in-loop
				redis.exceptions.ConnectionError,  # pylint: disable=dotted-import-in-loop
			):
				time.sleep(1)  # pylint: disable=dotted-import-in-loop

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
	con = None
	try:
		con = get_redis_connection(url=get_config().redis_internal_url, timeout=timeout, test_connection=test_connection)
		yield con
	finally:
		if con:
			con.close()


async def get_async_redis_connection(url: str, db: int = 0, timeout: int = 0, test_connection: bool = False) -> aioredis.StrictRedis:  # pylint: disable=invalid-name
	start = time.time()
	while True:
		try:  # pylint: disable=loop-try-except-usage
			con_id = f"{id(asyncio.get_running_loop())}/{url}/{db}"  # pylint: disable=dotted-import-in-loop
			new_pool = False
			async with aioredis_pool_lock:  # pylint: disable=loop-global-usage
				if con_id not in aioredis_connection_pool:  # pylint: disable=loop-global-usage
					new_pool = True
					aioredis_connection_pool[con_id] = aioredis.ConnectionPool.from_url(url, db=db)  # pylint: disable=dotted-import-in-loop,loop-global-usage
			# This will return a client (no Exception) even if connection is currently lost
			client = aioredis.StrictRedis(connection_pool=aioredis_connection_pool[con_id])  # pylint: disable=dotted-import-in-loop,loop-global-usage
			if new_pool or test_connection:
				await client.ping()
			return client
		except (aioredis.ConnectionError, aioredis.BusyLoadingError):  # pylint: disable=dotted-import-in-loop
			if timeout and time.time() - start >= timeout:  # pylint: disable=dotted-import-in-loop
				raise
			await asyncio.sleep(2)  # pylint: disable=dotted-import-in-loop


async def async_redis_client(timeout: int = 0, test_connection: bool = False) -> aioredis.StrictRedis:
	return await get_async_redis_connection(url=get_config().redis_internal_url, timeout=timeout, test_connection=test_connection)


async def async_get_redis_info(client: aioredis.StrictRedis) -> Dict[str, Any]:  # pylint: disable=too-many-locals
	stats_keys = []
	sessions_keys = []
	log_keys = []
	rpc_keys = []
	misc_keys = []
	redis_keys = client.scan_iter("opsiconfd:*")

	async for key in redis_keys:
		key = key.decode("utf8")
		if key.startswith("opsiconfd:stats:rpc") or key.startswith("opsiconfd:stats:num_rpc"):
			rpc_keys.append(key)
		elif key.startswith("opsiconfd:stats"):
			stats_keys.append(key)
		elif key.startswith("opsiconfd:sessions"):
			sessions_keys.append(key)
		elif key.startswith("opsiconfd:log"):
			log_keys.append(key)
		else:
			misc_keys.append(key)

	stats_memory = 0
	for key in stats_keys:
		stats_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0  # type: ignore[no-untyped-call]

	sessions_memory = 0
	for key in sessions_keys:
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
		"sessions": {"count": len(sessions_keys), "memory": sessions_memory},
		"logs": {"count": len(log_keys), "memory": logs_memory, "records": log_records},
		"rpc": {"count": len(rpc_keys), "memory": rpc_memory},
		"misc": {"count": len(misc_keys), "memory": misc_memory},
	}
	return redis_info


def remove_router(app: FastAPI, router: APIRouter, router_prefix: str) -> None:
	paths = [f"{router_prefix}{route.path}" for route in router.routes if isinstance(route, Route)]
	for route in app.routes:
		if isinstance(route, Route) and route.path in paths:
			app.routes.remove(route)


def remove_route_path(app: FastAPI, path: str) -> None:
	# Needs to be done twice to work for unknown reason
	for _ in range(2):
		for route in app.routes:
			if isinstance(route, Route) and route.path.lower().startswith(path.lower()):
				app.routes.remove(route)
