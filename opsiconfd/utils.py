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
from OpenSSL import crypto

from OPSI.Types import forceFqdn
from opsicommon.logging import handle_log_exception

REDIS_CONNECTION_RETRIES = 15



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

worker_num = 0 # pylint: disable=invalid-name
def get_worker_num():
	global worker_num # pylint: disable=global-statement, invalid-name
	if not worker_num:
		for (num, proc) in enumerate(get_worker_processes()):
			if proc.pid == os.getpid():
				worker_num = num + 1
				break
	return worker_num

_worker_processes_cache = {}
def get_worker_processes():
	# We need to always return the same objects
	# if not, cpu_percent(interval=None) will always return 0.0
	global _worker_processes_cache # pylint: disable=global-statement, invalid-name
	get_config()

	workers = []
	# process can be a worker with no children or an arbiter with children
	main_process = psutil.Process()
	if not main_process:
		return []

	children = main_process.children()
	if not children and (config.server_type != "uvicorn" or config.workers > 1):
		parent = main_process.parent()
		if parent:
			main_process = parent
			children = main_process.children()

	for proc in [main_process] + children:
		if config.server_type == "gunicorn" and not proc.children():  #proc.parent() and proc.parent().pid == main_process.pid:
			workers.append(proc)
		elif config.server_type == "uvicorn":
			if config.workers == 1 or "--multiprocessing-fork" in proc.cmdline():
				workers.append(proc)

	pids = []
	for worker in workers:
		pids.append(worker.pid)
		if not worker.pid in _worker_processes_cache:
			_worker_processes_cache[worker.pid] = worker

	for pid in list(_worker_processes_cache):
		if not pid in pids:
			del _worker_processes_cache[pid]

	return sorted(_worker_processes_cache.values(), key=lambda p: p.pid)


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

def read_ssl_ca_cert_file():
	get_config()
	with open(config.ssl_ca_cert) as f: # pylint: disable=invalid-name
		cacert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
		return crypto.dump_certificate(crypto.FILETYPE_PEM, cacert)


def retry_redis_call(func):
	@functools.wraps(func)
	def wrapper_retry(*args, **kwargs):
		for i in range(0,4):
			try:
				value = func(*args, **kwargs)
				return value
			except (
				aredis.exceptions.BusyLoadingError, redis.exceptions.BusyLoadingError,
				aredis.exceptions.ConnectionError,  redis.exceptions.ConnectionError):
				if i > 2:
					raise
				time.sleep(1)
	return wrapper_retry


def get_redis_connection(url, db=None, **kwargs): # pylint: disable=invalid-name
	count = 0
	while True:
		try:
			redis_client = redis.StrictRedis.from_url(url, db, **kwargs)
			redis_client.ping()
			break
		except (redis.exceptions.ConnectionError, redis.BusyLoadingError) as err:
			count += 1
			time.sleep(1)
			if count >= REDIS_CONNECTION_RETRIES:
				handle_log_exception(err)
				raise
	return redis_client


async def get_aredis_connection(url, db=None, **kwargs): # pylint: disable=invalid-name
	count = 0
	while True:
		try:
			redis_client = aredis.StrictRedis.from_url(url, db, **kwargs)
			await redis_client.ping()
			break
		except (aredis.exceptions.ConnectionError, aredis.BusyLoadingError) as err:
			count += 1
			asyncio.sleep(1)
			if count >= REDIS_CONNECTION_RETRIES:
				handle_log_exception(err)
				raise
	return redis_client
