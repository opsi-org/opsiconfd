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
import uvloop
import psutil
import aredis
import getpass

from .logging import logger, init_logging, start_redis_log_adapter_thread
from .config import config
from .application import application_setup
from .server import run_gunicorn, run_uvicorn
from .utils import get_node_name, get_worker_processes
from .setup import setup

async def update_worker_registry():
	redis = aredis.StrictRedis.from_url(config.redis_internal_url)
	node_name = get_node_name()
	while True:
		worker_num = 0
		for worker_num, proc in enumerate(get_worker_processes()):
			worker_num += 1
			redis_key = f"opsiconfd:worker_registry:{node_name}:{worker_num}"
			await redis.hmset(redis_key, {"worker_pid": proc.pid, "node_name": node_name, "worker_num": worker_num})
			await redis.expire(redis_key, 60)
		
		if worker_num == 0:
			# No worker, assuming we are in startup
			await asyncio.sleep(1)
			continue
		
		async for redis_key in redis.scan_iter(f"opsiconfd:worker_registry:{node_name}:*"):
			redis_key = redis_key.decode("utf-8")
			try:
				wn = int(redis_key.split(':')[-1])
			except Exception as exc:
				wn = -1
			if wn == -1 or wn > worker_num:
				await redis.delete(redis_key)
		
		for i in range(10):
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
		except Exception as exc:
			logger.error(exc, exc_info=True)
	
	async def main(self):
		self._loop.create_task(update_worker_registry())
		while True:
			await asyncio.sleep(1)

def main():
	if config.setup:
		init_logging(log_mode="local")
		setup(full=True)
		return

	redis_log_adapter_thread = None
	main_async_thread = None
	try:
		init_logging(log_mode=config.log_mode)
		if config.log_level_stderr > 0 or config.log_level_file > 0:
			running = threading.Event()
			redis_log_adapter_thread = start_redis_log_adapter_thread(running)
			running.wait()
		
		setup(full=False)
		
		if config.run_as_user and getpass.getuser() != config.run_as_user:
			logger.essential("Switching to user %s", config.run_as_user)
			try:
				user = pwd.getpwnam(config.run_as_user)
				gids = [user.pw_gid]
				for g in grp.getgrall():
					if user.pw_name in g.gr_mem and not g.gr_gid in gids:
						gids.append(g.gr_gid)
				logger.debug("Set uid=%s, gid=%s, groups=%s", user.pw_uid, gids[0], gids)
				os.setgid(gids[0])
				os.setgroups(gids)
				os.setuid(user.pw_uid)
				os.environ["HOME"] = user.pw_dir
			except Exception as e:
				raise Exception("Failed to run as user '{0}': {1}", config.run_as_user, e)
		
		# Do not use uvloop in redis logger thread because aiologger is currently incompatible with uvloop!
		# https://github.com/b2wdigital/aiologger/issues/38
		uvloop.install()

		logger.essential("opsiconfd is starting")
		logger.info("opsiconfd config:\n%s", pprint.pformat(config.items(), width=100, indent=4))

		main_async_thread = ArbiterAsyncMainThread()
		main_async_thread.daemon = True
		main_async_thread.start()
		
		if config.server_type == "gunicorn":
			run_gunicorn()
		elif config.server_type == "uvicorn":
			run_uvicorn()
	finally:
		if main_async_thread:
			main_async_thread.stop()
			main_async_thread.join()
		if redis_log_adapter_thread:
			redis_log_adapter_thread.stop()
			redis_log_adapter_thread.join()
