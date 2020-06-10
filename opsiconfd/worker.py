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
import socket
import typing
import functools
import asyncio
import aredis
import contextvars
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from starlette.concurrency import run_in_threadpool as starlette_run_in_threadpool

from .logging import logger, init_logging
from .config import config
from .utils import get_worker_num, get_node_name

contextvar_request_id = contextvars.ContextVar("request_id", default=None)
contextvar_client_session = contextvars.ContextVar("client_session", default=None)
contextvar_client_address = contextvars.ContextVar("client_address", default=None)
contextvar_server_address = contextvars.ContextVar("server_address", default=None)
contextvar_server_timing = contextvars.ContextVar("server_timing", default=None)

_redis_client = None
_pool_executor = None
_metrics_collector = None

async def get_redis_client():
	global _redis_client
	if not _redis_client:
		# The client automatically uses a connection from a connection pool for every command 
		_redis_client = aredis.StrictRedis.from_url(config.redis_internal_url, max_connections=config.executor_workers + 10)
		# _redis_client.flushdb()
	pool = _redis_client.connection_pool
	if len(pool._in_use_connections) >= pool.max_connections:
		logger.debug("No available connections in redis connection pool")
		while len(pool._in_use_connections) >= pool.max_connections:
			await asyncio.sleep(0.01)
	return _redis_client


def get_pool_executor():
	global _pool_executor
	if not _pool_executor:
		if config.executor_type == 'process':
			# process pool needs to pickle function arguments
			_pool_executor = ProcessPoolExecutor(max_workers=config.executor_workers)
		else:
			_pool_executor = ThreadPoolExecutor(max_workers=config.executor_workers)
	return _pool_executor

T = typing.TypeVar("T")
async def run_in_threadpool(func: typing.Callable[..., T], *args: typing.Any, **kwargs: typing.Any) -> T:
	return await starlette_run_in_threadpool(func, *args, **kwargs)

def get_metrics_collector():
	return _metrics_collector

def handle_asyncio_exception(loop, context):
	# context["message"] will always be there but context["exception"] may not
	msg = context.get("exception", context["message"])
	logger.error("Unhandled exception in asyncio loop '%s': %s", loop, msg)

def init_worker():
	global _metrics_collector
	init_logging()
	from .backend import get_backend
	from .statistics import MetricsCollector
	logger.notice("Init worker: %s", os.getpid())
	loop = asyncio.get_event_loop()
	loop.set_debug(config.debug)
	loop.set_default_executor(get_pool_executor())
	loop.set_exception_handler(handle_asyncio_exception)
	# create redis pool
	loop.create_task(get_redis_client())
	# create and start MetricsCollector
	# _metrics_collector = MetricsCollector(scope="worker")
	_metrics_collector = MetricsCollector()
	loop.create_task(_metrics_collector.main_loop())
	# create BackendManager instance
	get_backend()
