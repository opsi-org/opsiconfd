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
:license: GNU Affero General Public License version 3
"""

import os
import signal
import time
import threading
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor

try:
	# python3-pycryptodome installs into Cryptodome
	from Cryptodome.Hash import MD5 # type: ignore
	from Cryptodome.Signature import pkcs1_15 # type: ignore
except ImportError:
	# PyCryptodome from pypi installs into Crypto
	from Crypto.Hash import MD5
	from Crypto.Signature import pkcs1_15

from OPSI.Util import getPublicKey

from .config import config
from .logging import logger, init_logging
from .utils import get_node_name, get_worker_processes, get_aredis_connection
from .zeroconf import register_opsi_services, unregister_opsi_services
from .server import run_gunicorn, run_uvicorn
from .backend import get_backend

_arbiter_pid = None # pylint: disable=invalid-name

def set_arbiter_pid(pid: int) -> None:
	global _arbiter_pid # pylint: disable=global-statement, invalid-name
	_arbiter_pid = pid

def get_arbiter_pid() -> int:
	return _arbiter_pid

async def get_redis_client():
	return await get_aredis_connection(config.redis_internal_url)

last_reload_time = time.time()
def signal_handler(signum, frame): # pylint: disable=unused-argument
	global last_reload_time # pylint: disable=global-statement, invalid-name
	logger.info("Arbiter %s got signal %d", os.getpid(), signum)
	if signum == signal.SIGHUP and time.time() - last_reload_time > 2:
		last_reload_time = time.time()
		logger.notice("Arbiter %s reloading", os.getpid())
		config.reload()
		init_logging(log_mode=config.log_mode)

async def update_worker_registry():
	redis = await get_aredis_connection(config.redis_internal_url)
	node_name = get_node_name()
	num_workers = 0
	while True:
		worker_num = 0
		for worker_num, proc in enumerate(get_worker_processes()):
			worker_num += 1
			redis_key = f"opsiconfd:worker_registry:{node_name}:{worker_num}"
			await redis.hmset(redis_key, {
				"worker_pid": proc.pid,
				"node_name": node_name,
				"worker_num": worker_num
			})
			await redis.expire(redis_key, 60)

		if worker_num == 0:
			# No worker, assuming we are in startup
			await asyncio.sleep(1)
			continue

		if worker_num > num_workers:
			# New worker started
			pass
		elif worker_num < num_workers:
			# Worker crashed / killed
			logger.warning("Number of workers decreased from %d to %d", num_workers, worker_num)

		num_workers = worker_num

		async for redis_key in redis.scan_iter(f"opsiconfd:worker_registry:{node_name}:*"):
			redis_key = redis_key.decode("utf-8")
			try:
				wn = int(redis_key.split(':')[-1]) # pylint: disable=invalid-name
			except IndexError:
				wn = -1 # pylint: disable=invalid-name
			if wn == -1 or wn > num_workers:
				# Delete obsolete worker entry
				await redis.delete(redis_key)

		for _ in range(10):
			await asyncio.sleep(1)

class ArbiterAsyncMainThread(threading.Thread):
	def __init__(self):
		super().__init__()
		self.name = "ArbiterAsyncMainThread"
		self._loop = None

	def stop(self):
		unregister_opsi_services()
		if self._loop:
			self._loop.stop()

	def run(self):
		try:
			self._loop = asyncio.new_event_loop()
			self._loop.set_default_executor(
				ThreadPoolExecutor(
					max_workers=10,
					thread_name_prefix="arbiter-ThreadPoolExecutor"
				)
			)
			self._loop.set_debug(config.debug)
			asyncio.set_event_loop(self._loop)
			self._loop.create_task(self.main())
			self._loop.run_forever()
		except Exception as exc: # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

	async def main(self):
		# Need to reinit logging after server is initialized
		self._loop.call_later(3.0, init_logging, config.log_mode)
		self._loop.create_task(update_worker_registry())

		# Create and start MetricsCollector
		from .statistics import ArbiterMetricsCollector # pylint: disable=import-outside-toplevel
		metrics_collector = ArbiterMetricsCollector()
		self._loop.create_task(metrics_collector.main_loop())

		register_opsi_services()
		while True:
			await asyncio.sleep(1)

def main(): # pylint: disable=too-many-branches,too-many-statements
	set_arbiter_pid(os.getpid())
	signal.signal(signal.SIGHUP, signal_handler)

	main_async_thread = ArbiterAsyncMainThread()
	main_async_thread.daemon = True
	main_async_thread.start()

	if config.workers != 1:
		num_workers = 1
		backend_info = get_backend().backend_info()
		modules = backend_info['modules']
		helper_modules = backend_info['realmodules']

		if not all(key in modules for key in ('expires', 'customer')):
			logger.error(
				"Missing important information about modules. Probably no modules file installed. Limiting to %d workers.",
				num_workers
			)
		elif not modules.get('customer'):
			logger.error("No customer in modules file. Limiting to %d workers.", num_workers)
		elif not modules.get('valid'):
			logger.error("Modules file invalid. Limiting to %d workers.", num_workers)
		elif (
			modules.get('expires', '') != 'never' and
			time.mktime(time.strptime(modules.get('expires', '2000-01-01'), "%Y-%m-%d")) - time.time() <= 0
		):
			logger.error("Modules file expired. Limiting to %d workers.", num_workers)
		else:
			logger.info("Verifying modules file signature")
			public_key = getPublicKey(
				data=base64.decodebytes(
					b"AAAAB3NzaC1yc2EAAAADAQABAAABAQCAD/I79Jd0eKwwfuVwh5B2z+S8aV0C5s"
					b"uItJa18RrYip+d4P0ogzqoCfOoVWtDojY96FDYv+2d73LsoOckHCnuh55GA0mt"
					b"uVMWdXNZIE8Avt/RzbEoYGo/H0weuga7I8PuQNC/nyS8w3W8TH4pt+ZCjZZoX8"
					b"S+IizWCYwfqYoYTMLgB0i+6TCAfJj3mNgCrDZkQ24+rOFS4a8RrjamEz/b81no"
					b"Wl9IntllK1hySkR+LbulfTGALHgHkDUlk0OSu+zBPw/hcDSOMiDQvvHfmR4quG"
					b"Bhx4V8Eo2kNYstG2eJELrz7J1TJI0rCjpB+FQjYPsP2FOVm1TzE0bQPR+yLPbQ"
				)
			)
			data = ""
			mks = list(modules.keys())
			mks.sort()
			for module in mks:
				if module in ("valid", "signature"):
					continue
				if module in helper_modules:
					val = helper_modules[module]
					if int(val) > 0:
						modules[module] = True
				else:
					val = modules[module]
					if val is False:
						val = "no"
					if val is True:
						val = "yes"
				data += "%s = %s\r\n" % (module.lower().strip(), val)

			verified = False
			if modules["signature"].startswith("{"):
				s_bytes = int(modules['signature'].split("}", 1)[-1]).to_bytes(256, "big")
				try:
					pkcs1_15.new(public_key).verify(MD5.new(data.encode()), s_bytes)
					verified = True
				except ValueError:
					# Invalid signature
					pass
			else:
				h_int = int.from_bytes(MD5.new(data.encode()).digest(), "big")
				s_int = public_key._encrypt(int(modules["signature"])) # pylint: disable=protected-access
				verified = h_int == s_int

			if not verified:
				logger.error("Modules file invalid. Limiting to %d workers.", num_workers)
			else:
				logger.debug("Modules file signature verified (customer: %s)", modules.get('customer'))

				if modules.get("scalability1"):
					num_workers = config.workers
				else:
					logger.error("scalability1 missing in modules file. Limiting to %d workers.", num_workers)

		config.workers = num_workers

	if config.server_type == "gunicorn":
		run_gunicorn()
	elif config.server_type == "uvicorn":
		run_uvicorn()
