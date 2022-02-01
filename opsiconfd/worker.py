# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
worker
"""

import os
import gc
import ctypes
import signal
import asyncio
from types import FrameType
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from . import ssl
from .logging import logger, init_logging
from .config import config
from .utils import async_redis_client, get_manager_pid, Singleton
from .addon import AddonManager
from .application import app
from .metrics import WorkerMetricsCollector
from .backend import get_backend, get_client_backend


def init_pool_executor(loop: asyncio.AbstractEventLoop) -> None:
	# https://bugs.python.org/issue41699
	pool_executor = ThreadPoolExecutor(  # pylint: disable=consider-using-with
		max_workers=config.executor_workers, thread_name_prefix="worker-ThreadPoolExecutor"
	)
	loop.set_default_executor(pool_executor)


def memory_cleanup() -> None:
	gc.collect()
	ctypes.CDLL("libc.so.6").malloc_trim(0)


class Worker(metaclass=Singleton):
	def __init__(self) -> None:
		self.pid = os.getpid()
		self.is_manager = get_manager_pid() == self.pid
		self.worker_num = 1
		self._init_worker_num()
		self.metrics_collector = WorkerMetricsCollector(self.worker_num)

		logger.notice("Init worker %d (pid %s)", self.worker_num, os.getpid())
		loop = asyncio.get_event_loop()
		loop.set_debug(config.debug)
		init_pool_executor(loop)
		loop.set_exception_handler(self.handle_asyncio_exception)
		# create redis pool
		loop.create_task(async_redis_client())
		loop.create_task(self.main_loop())
		# Start MetricsCollector
		loop.create_task(self.metrics_collector.main_loop())

		# Create BackendManager instances
		get_backend()
		get_client_backend()

	def __repr__(self):
		return f"<{self.__class__.__name__} {self.worker_num} (pid: {self.pid}>"

	__str__ = __repr__

	def _init_worker_num(self) -> None:
		if self.is_manager:
			return

		worker_num = int(os.getenv("OPSICONFD_WORKER_WORKER_NUM", "0"))
		if worker_num > 0:
			self.worker_num = worker_num
		else:
			logger.error("Failed to get worker number from env")

		# Only if this process is a worker only process (multiprocessing)
		for sig in signal.SIGHUP, signal.SIGINT, signal.SIGTERM:
			signal.signal(sig, self.signal_handler)
		init_logging(log_mode=config.log_mode, is_worker=True)
		opsi_ca_key = os.getenv("OPSICONFD_WORKER_OPSI_SSL_CA_KEY", None)
		if opsi_ca_key:
			ssl.KEY_CACHE[config.ssl_ca_key] = opsi_ca_key
			del os.environ["OPSICONFD_WORKER_OPSI_SSL_CA_KEY"]

	def signal_handler(self, signum: int, frame: Optional[FrameType]) -> None:  # pylint: disable=unused-argument
		logger.info("Worker process %d (pid %d) received signal %d", self.worker_num, self.pid, signum)
		if signum == signal.SIGHUP:
			logger.notice("Worker process %d (pid %d) reloading", self.worker_num, self.pid)
			config.reload()
			init_logging(log_mode=config.log_mode, is_worker=True)
			memory_cleanup()
			AddonManager().reload_addons()
		else:
			app.is_shutting_down = True

	def handle_asyncio_exception(self, loop: asyncio.AbstractEventLoop, context: dict) -> None:
		# context["message"] will always be there but context["exception"] may not
		# msg = context.get("exception", context["message"])
		logger.error("Unhandled exception in worker %s asyncio loop '%s': %s", self, loop, context)

	async def main_loop(self) -> None:  # pylint: disable=no-self-use
		while True:
			await asyncio.sleep(120)
			memory_cleanup()
