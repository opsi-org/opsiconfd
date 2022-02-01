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
import threading
import asyncio
from types import FrameType
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from . import ssl
from .logging import logger, init_logging
from .config import config
from .utils import async_redis_client, get_manager_pid
from .addon import AddonManager
from .application import app
from .metrics import WorkerMetricsCollector


_worker_num = 1  # pylint: disable=invalid-name
_metrics_collector = WorkerMetricsCollector(_worker_num)  # pylint: disable=invalid-name


def set_worker_num(num: int) -> None:
	global _worker_num  # pylint: disable=global-statement,invalid-name
	_worker_num = num


def get_worker_num() -> int:
	return _worker_num


def init_pool_executor(loop: asyncio.AbstractEventLoop) -> None:
	# https://bugs.python.org/issue41699
	pool_executor = ThreadPoolExecutor(  # pylint: disable=consider-using-with
		max_workers=config.executor_workers, thread_name_prefix="worker-ThreadPoolExecutor"
	)
	loop.set_default_executor(pool_executor)


def get_metrics_collector() -> WorkerMetricsCollector:
	return _metrics_collector


def handle_asyncio_exception(loop: asyncio.AbstractEventLoop, context: dict) -> None:
	# context["message"] will always be there but context["exception"] may not
	# msg = context.get("exception", context["message"])
	logger.error("Unhandled exception in asyncio loop '%s': %s", loop, context)


def memory_cleanup() -> None:
	gc.collect()
	ctypes.CDLL("libc.so.6").malloc_trim(0)


def signal_handler(signum: int, frame: Optional[FrameType]) -> None:  # pylint: disable=unused-argument
	logger.info("Worker process %s received signal %d", os.getpid(), signum)
	if signum == signal.SIGHUP:
		logger.notice("Worker process %s reloading", os.getpid())
		config.reload()
		init_logging(log_mode=config.log_mode, is_worker=True)
		memory_cleanup()
		AddonManager().reload_addons()
	else:
		app.is_shutting_down = True


async def main_loop() -> None:
	while True:
		await asyncio.sleep(120)
		memory_cleanup()


def exit_worker() -> None:
	for thread in threading.enumerate():
		if hasattr(thread, "stop"):
			thread.stop()  # type: ignore[attr-defined]
		thread.join()


def init_worker() -> None:
	from .backend import get_backend, get_client_backend  # pylint: disable=import-outside-toplevel

	is_manager = get_manager_pid() == os.getpid()

	if not is_manager:
		worker_num = int(os.getenv("OPSICONFD_WORKER_WORKER_NUM", "0"))
		if worker_num > 0:
			set_worker_num(worker_num)
		else:
			logger.error("Failed to get worker number from env")

		# Only if this process is a worker only process (multiprocessing)
		for sig in signal.SIGHUP, signal.SIGINT, signal.SIGTERM:
			signal.signal(sig, signal_handler)
		init_logging(log_mode=config.log_mode, is_worker=True)
		opsi_ca_key = os.getenv("OPSICONFD_WORKER_OPSI_SSL_CA_KEY", None)
		if opsi_ca_key:
			ssl.KEY_CACHE[config.ssl_ca_key] = opsi_ca_key
			del os.environ["OPSICONFD_WORKER_OPSI_SSL_CA_KEY"]

	worker_num = get_worker_num()
	logger.notice("Init worker %d (pid %s)", worker_num, os.getpid())
	loop = asyncio.get_event_loop()
	loop.set_debug(config.debug)
	init_pool_executor(loop)
	loop.set_exception_handler(handle_asyncio_exception)
	# create redis pool
	loop.create_task(async_redis_client())
	loop.create_task(main_loop())
	# Start MetricsCollector
	_metrics_collector.set_worker_num(worker_num)
	loop.create_task(_metrics_collector.main_loop())
	# create BackendManager instances
	get_backend()
	get_client_backend()
