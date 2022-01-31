# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
manager
"""

import os
import signal
import time
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor

from .config import config
from .logging import logger, init_logging
from .utils import async_redis_client, async_get_redis_info, Singleton
from .zeroconf import register_opsi_services, unregister_opsi_services
from .server import Server
from .ssl import setup_server_cert


class Manager(metaclass=Singleton):  # pylint: disable=too-many-instance-attributes
	def __init__(self):
		self.pid = None
		self.running = False
		self._async_main_running = False
		self._loop = None
		self._last_reload = 0
		self._server = None
		self._should_stop = False
		self._server_cert_check_time = time.time()
		self._server_cert_check_interval = 24 * 3600
		self._redis_check_time = time.time()
		self._redis_check_interval = 300

	def stop(self, force=False):
		logger.notice("Manager stopping force=%s", force)
		if self._server:
			self._server.stop(force)
		self._should_stop = True
		for _ in range(5):
			if not self._async_main_running:
				break
			time.sleep(1)
		if self._loop:
			self._loop.stop()
			for _ in range(5):
				if not self._loop.is_running():
					break
				time.sleep(1)
		self.running = False

	def reload(self):
		self._last_reload = time.time()
		logger.notice("Manager process %s reloading", self.pid)
		config.reload()
		init_logging(log_mode=config.log_mode)
		if self._server:
			self._server.reload()

	def signal_handler(self, signum, frame):  # pylint: disable=unused-argument
		# <CTRL>+<C> will send SIGINT to the entire process group on linux.
		# So child processes will receive the SIGINT too.
		logger.info("Manager process %s received signal %d", self.pid, signum)
		if signum == signal.SIGHUP:
			if time.time() - self._last_reload > 2:
				self.reload()
		else:
			# Force on repetition
			self.stop(force=self._should_stop)

	def run(self):
		logger.info("Manager starting")
		self.running = True
		self._should_stop = False
		self.pid = os.getpid()
		self._last_reload = time.time()
		signal.signal(signal.SIGINT, self.signal_handler)  # Unix signal 2. Sent by Ctrl+C. Terminate service.
		signal.signal(signal.SIGTERM, self.signal_handler)  # Unix signal 15. Sent by `kill <pid>`. Terminate service.
		signal.signal(signal.SIGHUP, self.signal_handler)  # Unix signal 1. Sent by `kill -HUP <pid>`. Reload config.
		try:
			threading.Thread(name="ManagerAsyncLoop", daemon=True, target=self.run_loop).start()

			self._server = Server()
			self._server.run()

		except Exception as exc:  # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

	def run_loop(self):
		self._loop = asyncio.new_event_loop()
		self._loop.set_default_executor(ThreadPoolExecutor(max_workers=10, thread_name_prefix="manager-ThreadPoolExecutor"))
		self._loop.set_debug(config.debug)
		asyncio.set_event_loop(self._loop)
		self._loop.create_task(self.async_main())
		self._loop.run_forever()

	async def check_server_cert(self):
		if "ssl" not in (config.skip_setup or []):
			if setup_server_cert():
				logger.notice("Server certificate changed, restarting all workers")
				if self._server:
					self._server.restart_workers()
		self._server_cert_check_time = time.time()

	async def check_redis(self):
		redis_info = await async_get_redis_info(await async_redis_client())
		for key_type in redis_info["key_info"]:
			if redis_info["key_info"][key_type]["memory"] > 100_1000_1000:
				logger.warning("High redis memory usage for '%s': %s", key_type, redis_info["key_info"][key_type])
		self._redis_check_time = time.time()

	async def async_main(self):
		self._async_main_running = True
		# Create and start MetricsCollector
		from .statistics import ManagerMetricsCollector  # pylint: disable=import-outside-toplevel

		metrics_collector = ManagerMetricsCollector()
		self._loop.create_task(metrics_collector.main_loop())

		try:
			await register_opsi_services()
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to register opsi service via zeroconf: %s", err, exc_info=True)

		while not self._should_stop:
			try:
				now = time.time()
				if now - self._server_cert_check_time > self._server_cert_check_interval:
					await self.check_server_cert()
				if now - self._redis_check_time > self._redis_check_interval:
					await self.check_redis()
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
			for _num in range(60):
				if self._should_stop:
					break
				await asyncio.sleep(1)

		try:
			await unregister_opsi_services()
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to unregister opsi service via zeroconf: %s", err, exc_info=True)

		self._async_main_running = False
