# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
utils
"""

import socket
import string
import random
import ipaddress
import functools
import time
import asyncio
from contextlib import contextmanager
import psutil
import redis
import aredis
from dns import resolver, reversename


logger = None # pylint: disable=invalid-name
def get_logger():
	global logger # pylint: disable=global-statement, invalid-name
	if not logger:
		from .logging import logger # pylint: disable=import-outside-toplevel, redefined-outer-name
	return logger


config = None # pylint: disable=invalid-name
def get_config():
	global config # pylint: disable=global-statement, invalid-name
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
	with open("/proc/self/cgroup") as f: # pylint: disable=invalid-name
		for line in f.readlines():
			if line.split(':')[2].startswith("/docker/"):
				return True
	return False


node_name = None # pylint: disable=invalid-name
def get_node_name():
	global node_name # pylint: disable=global-statement, invalid-name
	if not node_name:
		node_name = get_config().node_name
		if not node_name:
			if running_in_docker():
				try:
					from .config import FQDN # pylint: disable=import-outside-toplevel
					ip = socket.gethostbyname(FQDN) # pylint: disable=invalid-name
					rev = reversename.from_address(ip)
					node_name = str(resolver.query(rev, "PTR")[0]).split('.')[0].replace("docker_", "")
				except resolver.NXDOMAIN as exc:
					get_logger().debug(exc)
					node_name = socket.gethostname()
			else:
				node_name = socket.gethostname()
	return node_name


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
async def get_aredis_connection(url: str, db: str = None, timeout: int = 0): # pylint: disable=invalid-name
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


async def aredis_client(timeout: int = 0):
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
	for key in log_keys:
		logs_memory += (await client.execute_command(f"MEMORY USAGE {key}")) or 0

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
			"memory": logs_memory
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
