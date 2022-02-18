# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
utils
"""

import socket
import os
import string
import random
import ipaddress
import functools
import datetime
import time
import codecs
import asyncio
import threading
from typing import Dict, Optional
from contextlib import contextmanager
from fastapi import FastAPI, APIRouter
from starlette.routing import Route
import psutil
import redis
import aioredis


logger = None  # pylint: disable=invalid-name
config = None  # pylint: disable=invalid-name
redis_pool_lock = threading.Lock()
aioredis_pool_lock = asyncio.Lock()
redis_connection_pool = {}
aioredis_connection_pool = {}


def get_logger():
	global logger  # pylint: disable=global-statement, invalid-name, global-variable-not-assigned
	if not logger:
		from .logging import logger  # pylint: disable=import-outside-toplevel, redefined-outer-name
	return logger


def get_config():
	global config  # pylint: disable=global-statement, invalid-name, global-variable-not-assigned
	if not config:
		from .config import config  # pylint: disable=import-outside-toplevel, redefined-outer-name
	return config


class Singleton(type):
	_instances: Dict[type, type] = {}

	def __call__(cls, *args, **kwargs):
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


def utc_time_timestamp():
	return datetime.datetime.utcnow().timestamp()


def running_in_docker():
	with codecs.open("/proc/self/cgroup", "r", "utf-8") as file:
		for line in file.readlines():
			if line.split(":")[2].startswith("/docker/"):
				return True
	return False


def is_manager(proc) -> bool:
	manager = False
	if proc.name() == "opsiconfd" or (
		proc.name() in ("python", "python3") and ("opsiconfd" in proc.cmdline() or "opsiconfd.__main__" in " ".join(proc.cmdline()))
	):
		manager = True
		for arg in proc.cmdline():
			if "multiprocessing" in arg or "log-viewer" in arg:
				manager = False
				break
	return manager


def get_manager_pid(ignore_self: bool = False, ignore_parents: bool = False) -> Optional[int]:
	manager_pid = None
	ignore_pids = []
	if ignore_self:
		our_pid = os.getpid()
		our_proc = psutil.Process(our_pid)
		ignore_pids += [our_pid]
		ignore_pids += [p.pid for p in our_proc.children(recursive=True)]
	if ignore_parents:
		ignore_pids += [p.pid for p in our_proc.parents()]

	for proc in psutil.process_iter():
		if proc.pid in ignore_pids or proc.status() == psutil.STATUS_ZOMBIE:
			continue
		if is_manager(proc) and (not manager_pid or proc.pid > manager_pid):
			# Do not return, prefer higher pids
			manager_pid = proc.pid

	return manager_pid


def decode_redis_result(_obj):
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


def normalize_ip_address(address, exploded=False):
	address = ipaddress.ip_address(address)
	if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
		address = address.ipv4_mapped
	if exploded:
		return address.exploded
	return address.compressed


def ip_address_to_redis_key(address):
	if ":" in address:
		# ipv6
		return normalize_ip_address(address, exploded=True).replace(":", ".")
	return address


def ip_address_from_redis_key(key):
	if key.count(".") > 3:
		# ipv6
		return key.replace(".", ":")
	return key


def get_ip_addresses():
	for interface, snics in psutil.net_if_addrs().items():
		for snic in snics:
			family = None
			if snic.family == socket.AF_INET:
				family = "ipv4"
			elif snic.family == socket.AF_INET6:
				family = "ipv6"
			else:
				continue

			ip_address = None
			try:
				ip_address = ipaddress.ip_address(snic.address.split("%")[0])
			except ValueError:
				logger.warning("Unrecognised ip address: %r", snic.address)

			yield {"family": family, "interface": interface, "address": snic.address, "ip_address": ip_address}


def get_random_string(length):
	letters = string.ascii_letters
	result_str = "".join(random.choice(letters) for i in range(length))
	return result_str


def retry_redis_call(func):
	@functools.wraps(func)
	def wrapper_retry(*args, **kwargs):  # pylint: disable=inconsistent-return-statements
		while True:
			try:
				return func(*args, **kwargs)
			except (
				aioredis.BusyLoadingError,
				redis.exceptions.BusyLoadingError,
				aioredis.ConnectionError,
				redis.exceptions.ConnectionError,
			):
				time.sleep(1)

	return wrapper_retry


def get_redis_connection(url: str, db: int = 0, timeout: int = 0) -> redis.StrictRedis:  # pylint: disable=invalid-name
	start = time.time()
	while True:
		try:
			con_id = f"{url}/{db}"
			new_pool = False
			with redis_pool_lock:
				if con_id not in redis_connection_pool:
					new_pool = True
					redis_connection_pool[con_id] = redis.ConnectionPool.from_url(url, db=db)
			client = redis.StrictRedis(connection_pool=redis_connection_pool[con_id])
			if new_pool:
				client.ping()
			return client
		except (redis.exceptions.ConnectionError, redis.BusyLoadingError):
			if timeout and timeout >= time.time() - start:
				raise
			time.sleep(2)


@contextmanager
def redis_client(timeout: int = 0):
	con = None
	try:
		con = get_redis_connection(url=get_config().redis_internal_url, timeout=timeout)
		yield con
	finally:
		if con:
			con.close()


async def get_async_redis_connection(url: str, db: str = None, timeout: int = 0) -> aioredis.StrictRedis:  # pylint: disable=invalid-name
	start = time.time()
	while True:
		try:
			con_id = f"{id(asyncio.get_event_loop())}/{url}/{db}"
			new_pool = False
			async with aioredis_pool_lock:
				if con_id not in aioredis_connection_pool:
					new_pool = True
					aioredis_connection_pool[con_id] = aioredis.ConnectionPool.from_url(url, db=db)
			# This will return a client (no Exception) even if connection is currently lost
			client = aioredis.StrictRedis(connection_pool=aioredis_connection_pool[con_id])
			if new_pool:
				await client.ping()
			return client
		except (aioredis.ConnectionError, aioredis.BusyLoadingError):
			if timeout and timeout >= time.time() - start:
				raise
			await asyncio.sleep(2)


async def async_redis_client(timeout: int = 0) -> aioredis.StrictRedis:
	return await get_async_redis_connection(url=get_config().redis_internal_url, timeout=timeout)


async def async_get_redis_info(client: aioredis.StrictRedis):  # pylint: disable=too-many-locals
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
		stats_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0

	sessions_memory = 0
	for key in sessions_keys:
		sessions_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0

	logs_memory = 0
	log_records = 0
	for key in log_keys:
		logs_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0
		log_records += (await client.execute_command(f"XLEN {key}")) or 0

	rpc_memory = 0
	for key in rpc_keys:
		rpc_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0

	misc_memory = 0
	for key in misc_keys:
		misc_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0

	redis_info = decode_redis_result(await client.execute_command("INFO"))
	redis_info["key_info"] = {
		"stats": {"count": len(stats_keys), "memory": stats_memory},
		"sessions": {"count": len(sessions_keys), "memory": sessions_memory},
		"logs": {"count": len(log_keys), "memory": logs_memory, "records": log_records},
		"rpc": {"count": len(rpc_keys), "memory": rpc_memory},
		"misc": {"count": len(misc_keys), "memory": misc_memory},
	}
	return redis_info


def remove_router(app: FastAPI, router: APIRouter, router_prefix: str):
	paths = [f"{router_prefix}{route.path}" for route in router.routes if isinstance(route, Route)]
	for route in app.routes:
		if isinstance(route, Route) and route.path in paths:
			app.routes.remove(route)


def remove_route_path(app: FastAPI, path: str):
	# Needs to be done twice to work for unknown reason
	for _ in range(2):
		for route in app.routes:
			if isinstance(route, Route) and route.path.lower().startswith(path.lower()):
				app.routes.remove(route)
