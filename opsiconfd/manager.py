# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
manager
"""

import asyncio
import os
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import FrameType

from .application import app
from .config import config
from .logging import init_logging, logger
from .messagebus.redis import cleanup_channels
from .metrics.collector import ManagerMetricsCollector
from .server import Server
from .ssl import setup_server_cert
from .utils import Singleton, async_get_redis_info, async_redis_client, log_config
from .zeroconf import register_opsi_services, unregister_opsi_services


class Manager(metaclass=Singleton):  # pylint: disable=too-many-instance-attributes
	def __init__(self) -> None:
		self.pid: int | None = None
		self.running = False
		self._async_main_running = False
		self._loop = asyncio.new_event_loop()
		self._last_reload = 0
		self._should_stop = False
		self._server_cert_check_time = time.time()
		self._redis_check_time = time.time()
		self._redis_check_interval = 300
		self._messagebus_channel_cleanup_time = 0.0
		self._messagebus_channel_cleanup_interval = 180
		self._server = Server()

	def stop(self, force: bool = False) -> None:
		logger.notice("Manager stopping force=%s", force)
		if self._server:
			self._server.stop(force)
		self._should_stop = True
		for _ in range(5):
			if not self._async_main_running:
				break
			time.sleep(1)  # pylint: disable=dotted-import-in-loop
		if self._loop:
			self._loop.stop()
			for _ in range(5):
				if not self._loop.is_running():
					break
				time.sleep(1)  # pylint: disable=dotted-import-in-loop
		self.running = False

	def reload(self) -> None:
		self._last_reload = int(time.time())
		logger.notice("Manager process %s reloading", self.pid)
		config.reload()
		init_logging(log_mode=config.log_mode)
		log_config()
		if self._server:
			self._server.reload()

	def signal_handler(self, signum: int, frame: FrameType | None) -> None:  # pylint: disable=unused-argument
		# <CTRL>+<C> will send SIGINT to the entire process group on linux.
		# So child processes will receive the SIGINT too.
		logger.info("Manager process %s received signal %d", self.pid, signum)
		if signum == signal.SIGHUP:
			if time.time() - self._last_reload > 2:
				self.reload()
		else:
			# Force on repetition
			self.stop(force=self._should_stop)

	def run(self) -> None:
		logger.info("Manager starting")
		self.running = True
		self._should_stop = False
		self.pid = os.getpid()
		self._last_reload = int(time.time())
		signal.signal(signal.SIGINT, self.signal_handler)  # Unix signal 2. Sent by Ctrl+C. Terminate service.
		signal.signal(signal.SIGTERM, self.signal_handler)  # Unix signal 15. Sent by `kill <pid>`. Terminate service.
		signal.signal(signal.SIGHUP, self.signal_handler)  # Unix signal 1. Sent by `kill -HUP <pid>`. Reload config.
		try:
			threading.Thread(name="ManagerAsyncLoop", daemon=True, target=self.run_loop).start()
			self._server.run()
		except Exception as exc:  # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

	def run_loop(self) -> None:
		self._loop.set_default_executor(ThreadPoolExecutor(max_workers=10, thread_name_prefix="manager-ThreadPoolExecutor"))
		self._loop.set_debug(config.debug)
		asyncio.set_event_loop(self._loop)
		self._loop.create_task(self.async_main())
		self._loop.run_forever()

	async def check_server_cert(self) -> None:
		if "server_cert" not in config.skip_setup:
			if setup_server_cert():
				logger.notice("Server certificate changed, restarting all workers")
				if self._server:
					self._server.restart_workers()
		self._server_cert_check_time = time.time()

	async def check_redis(self) -> None:
		redis_info = await async_get_redis_info(await async_redis_client())
		for key_type in redis_info["key_info"]:
			if redis_info["key_info"][key_type]["memory"] > 100_1000_1000:  # pylint: disable=loop-invariant-statement
				logger.warning(
					"High redis memory usage for '%s': %s",
					key_type,
					redis_info["key_info"][key_type],  # pylint: disable=loop-invariant-statement
				)  # pylint: disable=loop-invariant-statement
		self._redis_check_time = time.time()

	async def async_main(self) -> None:
		self._async_main_running = True
		# Create and start MetricsCollector
		metrics_collector = ManagerMetricsCollector()
		self._loop.create_task(metrics_collector.main_loop())

		if config.zeroconf:
			try:
				await register_opsi_services()
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to register opsi service via zeroconf: %s", err, exc_info=True)

		while not self._should_stop:
			try:  # pylint: disable=loop-try-except-usage
				now = time.time()  # pylint: disable=dotted-import-in-loop
				if now - self._server_cert_check_time > config.ssl_server_cert_check_interval:
					await self.check_server_cert()
				if now - self._redis_check_time > self._redis_check_interval:
					await self.check_redis()
				if now - self._messagebus_channel_cleanup_time > self._messagebus_channel_cleanup_interval:
					await cleanup_channels()
					self._messagebus_channel_cleanup_time = now
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
			for _num in range(60):
				if self._should_stop:
					break
				await asyncio.sleep(1)  # pylint: disable=dotted-import-in-loop

		if config.zeroconf:
			try:
				await unregister_opsi_services()
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to unregister opsi service via zeroconf: %s", err, exc_info=True)

		self._async_main_running = False
