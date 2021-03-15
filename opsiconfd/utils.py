# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:license: GNU Affero General Public License version 3
"""

import os
import socket
import string
import random
import ipaddress
import functools
import time
import asyncio
import psutil
import redis
import aredis
from dns import resolver, reversename

from OPSI.Types import forceFqdn


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
		return f.readline().split(':')[2].startswith("/docker/")

node_name = None # pylint: disable=invalid-name
def get_node_name():
	global node_name # pylint: disable=global-statement, invalid-name
	if not node_name:
		node_name = get_config().node_name
		if not node_name:
			if running_in_docker():
				try:
					ip = socket.gethostbyname(socket.getfqdn()) # pylint: disable=invalid-name
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

def get_fqdn(name=''):
	if not name:
		try:
			return forceFqdn(os.environ["OPSI_HOSTNAME"])
		except KeyError:
			# not set in environment.
			pass
	return forceFqdn(socket.getfqdn(name))

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
def get_redis_connection(url, db=None):  # pylint: disable=invalid-name
	while True:
		try:
			con_id = f"{url}/{db}"
			new_pool = False
			if not con_id in REDIS_CONNECTION_POOL:
				new_pool = True
				REDIS_CONNECTION_POOL[con_id] = redis.ConnectionPool.from_url(url, db)
			redis_client = redis.StrictRedis(connection_pool=REDIS_CONNECTION_POOL[con_id])
			if new_pool:
				redis_client.ping()
			return redis_client
		except (redis.exceptions.ConnectionError, redis.BusyLoadingError):
			time.sleep(2)

AREDIS_CONNECTION_POOL = {}
async def get_aredis_connection(url, db=None): # pylint: disable=invalid-name
	while True:
		try:
			con_id = f"{id(asyncio.get_event_loop())}/{url}/{db}"
			new_pool = False
			if con_id not in AREDIS_CONNECTION_POOL:
				new_pool = True
				AREDIS_CONNECTION_POOL[con_id] = aredis.ConnectionPool.from_url(url, db)
			redis_client = aredis.StrictRedis(connection_pool=AREDIS_CONNECTION_POOL[con_id])
			if new_pool:
				await redis_client.ping()
			return redis_client
		except (aredis.exceptions.ConnectionError, aredis.BusyLoadingError):
			await asyncio.sleep(2)
