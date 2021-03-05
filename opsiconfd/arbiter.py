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
from concurrent.futures import ThreadPoolExecutor

from .config import config
from .logging import logger, init_logging
from .utils import get_aredis_connection, Singleton
from .zeroconf import register_opsi_services, unregister_opsi_services
from .server import Server

def get_arbiter_pid() -> int:
	return Arbiter().pid

async def get_redis_client():
	return await get_aredis_connection(config.redis_internal_url)

class Arbiter(metaclass=Singleton):
	def __init__(self):
		self.pid = None
		self._loop = None
		self._last_reload = 0
		self._server = None
		self._should_stop = False

	def stop(self, force=False):
		logger.notice("Arbiter stopping force=%s", force)
		if self._server:
			self._server.stop(force)
		self._should_stop = True
		if self._loop:
			self._loop.stop()

	def reload(self):
		self._last_reload = time.time()
		logger.notice("Arbiter %s reloading", self.pid)
		config.reload()
		init_logging(log_mode=config.log_mode)
		if self._server:
			self._server.reload()

	def signal_handler(self, signum, frame): # pylint: disable=unused-argument
		# <CTRL>+<C> will send SIGINT to the entire process group on linux.
		# So child processes will receive the SIGINT too.
		logger.info("Arbiter %s got signal %d", self.pid, signum)
		if signum == signal.SIGHUP and time.time() - self._last_reload > 2:
			self.reload()
		else:
			# Force on repetition
			self.stop(force=self._should_stop)

	def run(self):
		logger.info("Arbiter starting")
		self.pid = os.getpid()
		self._last_reload = time.time()
		signal.signal(signal.SIGINT, self.signal_handler)  # Unix signal 2. Sent by Ctrl+C. Terminate service.
		signal.signal(signal.SIGTERM, self.signal_handler) # Unix signal 15. Sent by `kill <pid>`. Terminate service.
		signal.signal(signal.SIGHUP, self.signal_handler)  # Unix signal 1. Sent by `kill -HUP <pid>`. Reload config.
		try:
			loop_thread = threading.Thread(
				name="ArbiterAsyncLoop",
				daemon=True,
				target=self.run_loop
			)
			loop_thread.start()

			register_opsi_services()

			self._server = Server()
			self._server.run()

			unregister_opsi_services()
		except Exception as exc: # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

	def run_loop(self):
		self._loop = asyncio.new_event_loop()
		self._loop.set_default_executor(
			ThreadPoolExecutor(
				max_workers=10,
				thread_name_prefix="arbiter-ThreadPoolExecutor"
			)
		)
		self._loop.set_debug(config.debug)
		asyncio.set_event_loop(self._loop)
		self._loop.create_task(self.async_main())
		self._loop.run_forever()

	async def async_main(self):
		# Create and start MetricsCollector
		from .statistics import ArbiterMetricsCollector # pylint: disable=import-outside-toplevel
		metrics_collector = ArbiterMetricsCollector()
		self._loop.create_task(metrics_collector.main_loop())

		while not self._should_stop:
			await asyncio.sleep(1)
