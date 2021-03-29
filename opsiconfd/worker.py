# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import os
import gc
import ctypes
import signal
import threading
import asyncio
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import redis

from .logging import logger, init_logging
from .config import config
from .utils import get_aredis_connection
from .arbiter import get_arbiter_pid
from . import ssl

_redis_client = None # pylint: disable=invalid-name
_metrics_collector = None # pylint: disable=invalid-name
_redis_pool = None # pylint: disable=invalid-name
_worker_num = 1 # pylint: disable=invalid-name

def set_worker_num(num):
	global _worker_num # pylint: disable=global-statement,invalid-name
	_worker_num = num

def get_worker_num():
	return _worker_num

@contextmanager
def sync_redis_client():
	global _redis_pool # pylint: disable=global-statement,invalid-name
	if not _redis_pool:
		_redis_pool = redis.BlockingConnectionPool.from_url(
			url=config.redis_internal_url
		)
	con = None
	try:
		con = redis.Redis(connection_pool=_redis_pool)
		yield con
	finally:
		if con:
			con.close()

async def get_redis_client():
	global _redis_client # pylint: disable=global-statement, invalid-name
	if not _redis_client:
		_redis_client = await get_aredis_connection(config.redis_internal_url)
		# _redis_client.flushdb()
	try:
		pool = _redis_client.connection_pool
		if len(pool._in_use_connections) >= pool.max_connections: # pylint: disable=protected-access
			logger.warning("No available connections in redis connection pool")
			while len(pool._in_use_connections) >= pool.max_connections: # pylint: disable=protected-access
				await asyncio.sleep(0.01)
		return _redis_client
	except Exception as err: # pylint: disable=broad-except
		logger.error(err, exc_info=True)

def init_pool_executor(loop):
	# https://bugs.python.org/issue41699
	pool_executor = ThreadPoolExecutor(
		max_workers=config.executor_workers,
		thread_name_prefix="worker-ThreadPoolExecutor"
	)
	loop.set_default_executor(pool_executor)

def get_metrics_collector():
	return _metrics_collector

def handle_asyncio_exception(loop, context):
	# context["message"] will always be there but context["exception"] may not
	#msg = context.get("exception", context["message"])
	logger.error("Unhandled exception in asyncio loop '%s': %s", loop, context)

def memory_cleanup():
	gc.collect()
	ctypes.CDLL("libc.so.6").malloc_trim(0)

def signal_handler(signum, frame): # pylint: disable=unused-argument
	logger.info("Worker process %s received signal %d", os.getpid(), signum)
	if signum == signal.SIGHUP:
		logger.notice("Worker process %s reloading", os.getpid())
		config.reload()
		init_logging(log_mode=config.log_mode, is_worker=True)
		memory_cleanup()

async def main_loop():
	while True:
		await asyncio.sleep(120)
		memory_cleanup()

def exit_worker():
	for thread in threading.enumerate():
		if hasattr(thread, "stop"):
			thread.stop()
			thread.join()

def init_worker():
	global _metrics_collector # pylint: disable=global-statement, invalid-name
	from .backend import get_backend, get_client_backend # pylint: disable=import-outside-toplevel
	from .statistics import WorkerMetricsCollector # pylint: disable=import-outside-toplevel
	is_arbiter = get_arbiter_pid() == os.getpid()

	if not is_arbiter:
		try:
			set_worker_num(int(os.getenv("OPSICONFD_WORKER_WORKER_NUM")))
		except Exception as err: # pylint: disable=broad-except
			logger.error("Failed to get worker number from env: %s", err)
		# Only if this process is a worker only process (multiprocessing)
		signal.signal(signal.SIGHUP, signal_handler)
		init_logging(log_mode=config.log_mode, is_worker=True)
		opsi_ca_key = os.getenv("OPSICONFD_WORKER_OPSI_SSL_CA_KEY", None)
		if opsi_ca_key:
			ssl.KEY_CACHE[config.ssl_ca_key] = opsi_ca_key
			del os.environ["OPSICONFD_WORKER_OPSI_SSL_CA_KEY"]

	logger.notice("Init worker %d (pid %s)", get_worker_num(), os.getpid())
	loop = asyncio.get_event_loop()
	loop.set_debug(config.debug)
	init_pool_executor(loop)
	loop.set_exception_handler(handle_asyncio_exception)
	# create redis pool
	loop.create_task(get_redis_client())
	loop.create_task(main_loop())
	# create and start MetricsCollector
	_metrics_collector = WorkerMetricsCollector()
	loop.create_task(_metrics_collector.main_loop())
	# create BackendManager instances
	get_backend()
	get_client_backend()
