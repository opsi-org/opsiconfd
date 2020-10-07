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
import pwd
import grp
import threading
import pprint
import asyncio
import getpass
import uvloop
import aredis
import time
import base64
import psutil
import signal
try:
	# python3-pycryptodome installs into Cryptodome
	from Cryptodome.Hash import MD5
	from Cryptodome.Signature import pkcs1_15
except ImportError:
	# PyCryptodome from pypi installs into Crypto
	from Crypto.Hash import MD5
	from Crypto.Signature import pkcs1_15

from OPSI import __version__ as python_opsi_version
from OPSI.Util import getPublicKey

from . import __version__
from .logging import logger, init_logging
from .config import config
from .server import run_gunicorn, run_uvicorn
from .utils import get_node_name, get_worker_processes
from .setup import setup
from .patch import apply_patches
from .backend import get_backend
from .worker import set_arbiter_pid

async def update_worker_registry():
	redis = aredis.StrictRedis.from_url(config.redis_internal_url)
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
				wn = int(redis_key.split(':')[-1])
			except IndexError:
				wn = -1
			if wn == -1 or wn > num_workers:
				# Delete obsolete worker entry
				await redis.delete(redis_key)
		
		for _ in range(10):
			await asyncio.sleep(1)

class ArbiterAsyncMainThread(threading.Thread):
	def __init__(self):
		super().__init__()
		self._loop = None
	
	def stop(self):
		if self._loop:
			self._loop.stop()

	def run(self):
		try:
			self._loop = asyncio.new_event_loop()
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
		while True:
			await asyncio.sleep(1)

last_reload_time = time.time()
def signal_handler(signum, frame):
	global last_reload_time
	logger.info("Arbiter %s got signal %d", os.getpid(), signum)
	if signum == signal.SIGHUP and time.time() - last_reload_time > 2:
		last_reload_time = time.time()
		logger.notice("Arbiter %s reloading", os.getpid())
		config.reload()
		init_logging(log_mode=config.log_mode)

def main():
	if config.version:
		print(f"{__version__} [python-opsi={python_opsi_version}]")
		return
	
	if config.action == "setup" or config.setup:
		init_logging(log_mode="local")
		setup(full=True)
		return

	if config.action in ("reload", "stop"):
		send_signal = signal.SIGINT if config.action == "stop" else signal.SIGHUP
		our_pid = os.getpid()
		our_proc = psutil.Process(our_pid)
		ignore_pids = [our_pid]
		ignore_pids += [p.pid for p in our_proc.children(recursive=True)]
		ignore_pids += [p.pid for p in our_proc.parents()]
		pids = []
		for proc in psutil.process_iter():
			if proc.pid in ignore_pids:
				continue
			if proc.name() == "opsiconfd":
				pids.append(proc.pid)
				pids.extend([p.pid for p in proc.children(recursive=True)])
			elif proc.name() in ("python", "python3"):
				for arg in proc.cmdline():
					if arg.find("opsiconfd.__main__") != -1:
						pids.append(proc.pid)
						pids.extend([p.pid for p in proc.children(recursive=True)])
						break
		for pid in sorted(set(pids), reverse=True):
			os.kill(pid, send_signal)
		return

	set_arbiter_pid(os.getpid())
	signal.signal(signal.SIGHUP, signal_handler)
	apply_patches()
	
	try:
		init_logging(log_mode=config.log_mode)
		
		setup(full=False)
		
		if config.run_as_user and getpass.getuser() != config.run_as_user:
			logger.essential("Switching to user %s", config.run_as_user)
			try:
				user = pwd.getpwnam(config.run_as_user)
				gids = os.getgrouplist(user.pw_name, user.pw_gid)
				for g in grp.getgrall():
					if user.pw_name in g.gr_mem and not g.gr_gid in gids:
						gids.append(g.gr_gid)
				logger.debug("Set uid=%s, gid=%s, groups=%s", user.pw_uid, gids[0], gids)
				os.setgid(gids[0])
				os.setgroups(gids)
				os.setuid(user.pw_uid)
				os.environ["HOME"] = user.pw_dir
			except Exception as e:
				raise Exception(f"Failed to run as user '{config.run_as_user}': {e}")
		
		# Do not use uvloop in redis logger thread because aiologger is currently incompatible with uvloop!
		# https://github.com/b2wdigital/aiologger/issues/38
		uvloop.install()

		logger.essential("opsiconfd is starting")
		logger.info("opsiconfd config:\n%s", pprint.pformat(config.items(), width=100, indent=4))

		main_async_thread = ArbiterAsyncMainThread()
		main_async_thread.daemon = True
		main_async_thread.start()
		
		if config.workers != 1:
			num_workers = 1
			backend_info = get_backend().backend_info()
			modules = backend_info['modules']
			helper_modules = backend_info['realmodules']

			if not all(key in modules for key in ('expires', 'customer')):
				logger.error("Missing important information about modules. Probably no modules file installed. Limiting to %d workers.", num_workers)
			elif not modules.get('customer'):
				logger.error("No customer in modules file. Limiting to %d workers.", num_workers)
			elif not modules.get('valid'):
				logger.error("Modules file invalid. Limiting to %d workers.", num_workers)
			elif (modules.get('expires', '') != 'never') and (time.mktime(time.strptime(modules.get('expires', '2000-01-01'), "%Y-%m-%d")) - time.time() <= 0):
				logger.error("Modules file expired. Limiting to %d workers.", num_workers)
			else:
				logger.info("Verifying modules file signature")
				publicKey = getPublicKey(data=base64.decodebytes(b"AAAAB3NzaC1yc2EAAAADAQABAAABAQCAD/I79Jd0eKwwfuVwh5B2z+S8aV0C5suItJa18RrYip+d4P0ogzqoCfOoVWtDojY96FDYv+2d73LsoOckHCnuh55GA0mtuVMWdXNZIE8Avt/RzbEoYGo/H0weuga7I8PuQNC/nyS8w3W8TH4pt+ZCjZZoX8S+IizWCYwfqYoYTMLgB0i+6TCAfJj3mNgCrDZkQ24+rOFS4a8RrjamEz/b81noWl9IntllK1hySkR+LbulfTGALHgHkDUlk0OSu+zBPw/hcDSOMiDQvvHfmR4quGyLPbQ2FOVm1TzE0bQPR+Bhx4V8Eo2kNYstG2eJELrz7J1TJI0rCjpB+FQjYPsP"))
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
						pkcs1_15.new(publicKey).verify(MD5.new(data.encode()), s_bytes)
						verified = True
					except ValueError:
						# Invalid signature
						pass
				else:
					h_int = int.from_bytes(MD5.new(data.encode()).digest(), "big")
					s_int = publicKey._encrypt(int(modules["signature"]))
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
	
	finally:
		for t in threading.enumerate():
			if hasattr(t, "stop"):
				t.stop()
				t.join()
	