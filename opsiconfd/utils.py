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
import time
import codecs
import asyncio
from contextlib import contextmanager
from fastapi import FastAPI, APIRouter
import psutil
import redis
import aredis


logger = None # pylint: disable=invalid-name
def get_logger():
	global logger # pylint: disable=global-statement, invalid-name, global-variable-not-assigned
	if not logger:
		from .logging import logger # pylint: disable=import-outside-toplevel, redefined-outer-name
	return logger


config = None # pylint: disable=invalid-name
def get_config():
	global config # pylint: disable=global-statement, invalid-name, global-variable-not-assigned
	if not config:
		from .config import config # pylint: disable=import-outside-toplevel, redefined-outer-name
	return config


class Singleton(type):
	_instances = {}
	def __call__(cls, *args, **kwargs):
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


def running_in_docker():
	with codecs.open("/proc/self/cgroup", "r", "utf-8") as file:
		for line in file.readlines():
			if line.split(':')[2].startswith("/docker/"):
				return True
	return False

def is_manager(proc) -> bool:
	manager = False
	if (
		proc.name() == "opsiconfd" or
		(proc.name() in ("python", "python3") and (
			"opsiconfd" in proc.cmdline() or
			"opsiconfd.__main__" in " ".join(proc.cmdline())
		))
	):
		manager = True
		for arg in proc.cmdline():
			if "multiprocessing" in arg or "log-viewer" in arg:
				manager = False
				break
	return manager

def get_manager_pid(ignore_self: bool = False) -> int:
	manager_pid = None
	ignore_pids = []
	if ignore_self:
		our_pid = os.getpid()
		our_proc = psutil.Process(our_pid)
		ignore_pids = [our_pid]
		ignore_pids += [p.pid for p in our_proc.children(recursive=True)]
		ignore_pids += [p.pid for p in our_proc.parents()]

	for proc in psutil.process_iter():
		if proc.pid in ignore_pids:
			continue
		if is_manager(proc) and (not manager_pid or proc.pid > manager_pid):
			# Do not return, prefer higher pids
			manager_pid = proc.pid

	return manager_pid

def decode_redis_result(_obj):
	if isinstance(_obj, bytes):
		_obj = _obj.decode("utf8")
	elif isinstance(_obj, list):
		for i in range(len(_obj)): # pylint: disable=consider-using-enumerate
			_obj[i] = decode_redis_result(_obj[i])
	elif isinstance(_obj, dict):
		for (k, v) in _obj.items(): # pylint: disable=invalid-name
			_obj[decode_redis_result(k)] = decode_redis_result(v)
	elif isinstance(_obj, set):
		for v in _obj: # pylint: disable=invalid-name
			_obj.remove(v)
			_obj.add(decode_redis_result(v))
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
				ip_address = ipaddress.ip_address(snic.address.split('%')[0])
			except ValueError:
				logger.warning("Unrecognised ip address: %r", snic.address)

			yield {
				"family": family,
				"interface": interface,
				"address": snic.address,
				"ip_address": ip_address
			}


def get_random_string(length):
	letters = string.ascii_letters
	result_str = ''.join(random.choice(letters) for i in range(length))
	return result_str


def retry_redis_call(func):
	@functools.wraps(func)
	def wrapper_retry(*args, **kwargs):  # pylint: disable=inconsistent-return-statements
		while True:
			try:
				return func(*args, **kwargs)
			except (
				aredis.exceptions.BusyLoadingError, redis.exceptions.BusyLoadingError,
				aredis.exceptions.ConnectionError, redis.exceptions.ConnectionError
			):
				time.sleep(1)
	return wrapper_retry


REDIS_CONNECTION_POOL = {}
def get_redis_connection(url: str, db: str = None, timeout: int = 0):  # pylint: disable=invalid-name
	start = time.time()
	while True:
		try:
			con_id = f"{url}/{db}"
			new_pool = False
			if not con_id in REDIS_CONNECTION_POOL:
				new_pool = True
				REDIS_CONNECTION_POOL[con_id] = redis.ConnectionPool.from_url(url, db)
			client = redis.StrictRedis(connection_pool=REDIS_CONNECTION_POOL[con_id])
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


AREDIS_CONNECTION_POOL = {}
async def get_aredis_connection(url: str, db: str = None, timeout: int = 0) -> aredis.StrictRedis: # pylint: disable=invalid-name
	start = time.time()
	while True:
		try:
			con_id = f"{id(asyncio.get_event_loop())}/{url}/{db}"
			new_pool = False
			if con_id not in AREDIS_CONNECTION_POOL:
				new_pool = True
				AREDIS_CONNECTION_POOL[con_id] = aredis.ConnectionPool.from_url(url, db)
			# This will return a client (no Exception) even if connection is currently lost
			client = aredis.StrictRedis(connection_pool=AREDIS_CONNECTION_POOL[con_id])
			if new_pool:
				await client.ping()
			return client
		except (aredis.exceptions.ConnectionError, aredis.BusyLoadingError) as err:
			print("ERROR", err)
			if timeout and timeout >= time.time() - start:
				raise
			await asyncio.sleep(2)


async def aredis_client(timeout: int = 0) -> aredis.StrictRedis:
	return await get_aredis_connection(url=get_config().redis_internal_url, timeout=timeout)


async def get_aredis_info(client: aredis.StrictRedis):	# pylint: disable=too-many-locals
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
		"stats": {
			"count": len(stats_keys),
			"memory": stats_memory
		},
		"sessions": {
			"count": len(sessions_keys),
			"memory": sessions_memory
		},
		"logs": {
			"count": len(log_keys),
			"memory": logs_memory,
			"records": log_records
		},
		"rpc": {
			"count": len(rpc_keys),
			"memory": rpc_memory
		},
		"misc": {
			"count": len(misc_keys),
			"memory": misc_memory
		}
	}
	return redis_info

def remove_router(app: FastAPI, router: APIRouter, router_prefix: str):
	paths = [f"{router_prefix}{route.path}" for route in router.routes]
	for route in app.routes:
		if route.path in paths:
			app.routes.remove(route)
