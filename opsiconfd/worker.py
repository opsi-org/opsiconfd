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
import typing
import signal
import threading
import asyncio
import contextvars
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

import redis
from starlette.concurrency import run_in_threadpool as starlette_run_in_threadpool

from .logging import logger, init_logging
from .config import config
from .utils import get_aredis_connection
from .arbiter import get_arbiter_pid

contextvar_request_id = contextvars.ContextVar("request_id", default=None)
contextvar_client_session = contextvars.ContextVar("client_session", default=None)
contextvar_client_address = contextvars.ContextVar("client_address", default=None)
contextvar_server_timing = contextvars.ContextVar("server_timing", default=None)

_redis_client = None # pylint: disable=invalid-name
_pool_executor = None # pylint: disable=invalid-name
_metrics_collector = None # pylint: disable=invalid-name
_redis_pool = None # pylint: disable=invalid-name

@contextmanager
def sync_redis_client():
	global _redis_pool # pylint: disable=global-statement, invalid-name
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
		# The client automatically uses a connection from a connection pool for every command
		#max_connections = int(config.executor_workers * 2)
		_redis_client = await get_aredis_connection(config.redis_internal_url)#, max_connections=max_connections)
		# _redis_client.flushdb()
	try:
		pool = _redis_client.connection_pool
		#logger.devel(len(pool._in_use_connections))
		if len(pool._in_use_connections) >= pool.max_connections: # pylint: disable=protected-access
			logger.warning("No available connections in redis connection pool")
			while len(pool._in_use_connections) >= pool.max_connections: # pylint: disable=protected-access
				await asyncio.sleep(0.01)
		return _redis_client
	except Exception as err: # pylint: disable=broad-except
		logger.error(err, exc_info=True)

def get_pool_executor():
	global _pool_executor # pylint: disable=global-statement, invalid-name
	if not _pool_executor:
		if config.executor_type == 'process':
			# process pool needs to pickle function arguments
			_pool_executor = ProcessPoolExecutor(max_workers=config.executor_workers)
		else:
			_pool_executor = ThreadPoolExecutor(
				max_workers=config.executor_workers,
				thread_name_prefix="worker-ThreadPoolExecutor"
			)
			# Start all worker threads in pool.
			# This will speed up calls to run_in_threadpool().
			for _ in range(config.executor_workers):
				_pool_executor._adjust_thread_count() # pylint: disable=protected-access
	return _pool_executor

T = typing.TypeVar("T") # pylint: disable=invalid-name
async def run_in_threadpool(func: typing.Callable[..., T], *args: typing.Any, **kwargs: typing.Any) -> T:
	return await starlette_run_in_threadpool(func, *args, **kwargs)

def get_metrics_collector():
	return _metrics_collector

def handle_asyncio_exception(loop, context):
	# context["message"] will always be there but context["exception"] may not
	#msg = context.get("exception", context["message"])
	logger.error("Unhandled exception in asyncio loop '%s': %s", loop, context)

def signal_handler(signum, frame): # pylint: disable=unused-argument
	logger.info("Worker %s got signal %d", os.getpid(), signum)
	if signum == signal.SIGHUP:
		logger.notice("Worker %s reloading", os.getpid())
		config.reload()
		init_logging(log_mode=config.log_mode, is_worker=True)
	else:
		exit_worker()

def exit_worker():
	if _pool_executor:
		_pool_executor.shutdown()
	for t in threading.enumerate(): # pylint: disable=invalid-name
		if hasattr(t, "stop"):
			t.stop()
			t.join()

def init_worker():
	global _metrics_collector # pylint: disable=global-statement, invalid-name
	from .backend import get_backend, get_client_backend # pylint: disable=import-outside-toplevel
	from .statistics import WorkerMetricsCollector # pylint: disable=import-outside-toplevel
	is_arbiter = get_arbiter_pid() == os.getpid()

	if not is_arbiter:
		# Only if this process is a worker only process (multiprocessing)
		signal.signal(signal.SIGINT, signal_handler)
		signal.signal(signal.SIGHUP, signal_handler)
		init_logging(log_mode=config.log_mode, is_worker=True)

	logger.notice("Init worker (pid %s)", os.getpid())
	loop = asyncio.get_event_loop()
	loop.set_debug(config.debug)
	loop.set_default_executor(get_pool_executor())
	loop.set_exception_handler(handle_asyncio_exception)
	# create redis pool
	loop.create_task(get_redis_client())
	# create and start MetricsCollector
	_metrics_collector = WorkerMetricsCollector()
	loop.create_task(_metrics_collector.main_loop())
	# create BackendManager instances
	get_backend()
	get_client_backend()
