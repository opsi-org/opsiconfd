# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
worker
"""

from __future__ import annotations

import asyncio
import ctypes
import gc
import multiprocessing
import os
import socket
import sys
import time
from asyncio import sleep as asyncio_sleep
from concurrent.futures import ThreadPoolExecutor
from enum import StrEnum
from logging import DEBUG
from multiprocessing.context import SpawnProcess
from signal import SIGHUP
from typing import TYPE_CHECKING, Any, Callable, Optional

from opsicommon.utils import (
	ip_address_in_network,
	patch_popen,  # type: ignore[import]
)
from uvicorn.config import Config  # type: ignore[import]
from uvicorn.server import Server as UvicornServer  # type: ignore[import]

from opsiconfd import __version__
from opsiconfd.addon import AddonManager
from opsiconfd.application import AppState, MaintenanceState, app
from opsiconfd.backend import get_protected_backend, get_unprotected_backend
from opsiconfd.config import GC_THRESHOLDS, config, configure_warnings, opsi_config
from opsiconfd.logging import init_logging, logger, shutdown_logging
from opsiconfd.metrics.collector import WorkerMetricsCollector
from opsiconfd.redis import async_redis_client, pool_disconnect_connections
from opsiconfd.ssl import opsi_ca_is_self_signed
from opsiconfd.utils import asyncio_create_task

if TYPE_CHECKING:
	from uvicorn.protocols.http.h11_impl import H11Protocol
	from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
	from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol
	from uvicorn.protocols.websockets.wsproto_impl import WSProtocol


multiprocessing.allow_connection_pickling()
spawn = multiprocessing.get_context("spawn")


def init_pool_executor(loop: asyncio.AbstractEventLoop) -> None:
	# https://bugs.python.org/issue41699
	pool_executor = ThreadPoolExecutor(  # pylint: disable=consider-using-with
		max_workers=config.executor_workers, thread_name_prefix="worker-ThreadPoolExecutor"
	)
	loop.set_default_executor(pool_executor)


def memory_cleanup() -> None:
	gc.collect()
	ctypes.CDLL("libc.so.6").malloc_trim(0)


def get_uvicorn_config() -> Config:
	options = {
		"loop": "uvloop",
		"interface": "asgi3",
		"http": "h11",  # "httptools"
		# Using wsproto instead of websockets because of error:
		# Websocket connection closed with error: no close frame received or sent
		# Reproducable with one worker and:
		#  perftest/messagebus-clients.py --clients 500 --events 0 --start-gap 20 --keep-connection
		"ws": "wsproto",  # "websockets"
		"host": config.interface,
		"port": config.port,
		"workers": config.workers,
		"log_config": None,
		"date_header": False,
		"server_header": False,
		"headers": [["Server", f"opsiconfd {__version__} (uvicorn)"], ["X-opsi-server-role", opsi_config.get("host", "server-role")]],
		# https://veithen.io/2014/01/01/how-tcp-backlog-works-in-linux.html
		"backlog": config.socket_backlog,
		"timeout_keep_alive": 5,
		"ws_per_message_deflate": False,
		"ws_max_queue": config.websocket_queue_size,
		"ws_ping_interval": 15,
		"ws_ping_timeout": 10,
	}

	if config.ssl_server_key and config.ssl_server_cert:
		options["ssl_keyfile"] = config.ssl_server_key
		options["ssl_keyfile_password"] = config.ssl_server_key_passphrase
		options["ssl_certfile"] = config.ssl_server_cert
		options["ssl_ciphers"] = config.ssl_ciphers
		if not opsi_ca_is_self_signed():
			# Only send the ca cert if it is not self-signed otherwise it can lead to SSL error:
			# self signed certificate in certificate chain
			options["ssl_ca_certs"] = config.ssl_ca_cert

	return Config("opsiconfd.application:app", **options)


class WorkerState(StrEnum):
	INIT = "init"
	STARTING = "starting"
	RUNNING = "running"
	VANISHED = "vanished"
	STOPPING = "stopping"
	STOPPED = "stopped"


class WorkerInfo:  # pylint: disable = too-few-public-methods
	def __init__(  # pylint: disable = too-many-arguments
		self, node_name: str, worker_num: int, create_time: float = 0.0, pid: int = 0, app_state: str = ""
	) -> None:
		self.node_name = node_name
		self.worker_num = worker_num
		self.create_time = create_time
		self.worker_state = WorkerState.INIT
		self.pid = pid
		self.app_state = app_state
		self.redis_state_key_expire = 60

	@classmethod
	def from_dict(cls, data: dict) -> WorkerInfo:
		kwargs = {}
		for key, val in data.items():
			if isinstance(key, bytes):
				key = key.decode("utf-8")
			if isinstance(val, bytes):
				val = val.decode("utf-8")
			if key == "node_name":
				pass
			elif key in ("worker_num", "pid"):
				val = int(val)
			elif key == "create_time":
				val = float(val)
			else:
				continue
			kwargs[key] = val
		return WorkerInfo(**kwargs)

	@property
	def id(self) -> str:  # pylint: disable=invalid-name
		return f"{self.node_name}:{self.worker_num}"

	@property
	def redis_state_key(self) -> str:  # pylint: disable=invalid-name
		return f"{config.redis_key('state')}:workers:{self.id}"

	def __repr__(self) -> str:
		return f"Worker(id={self.id!r} pid={self.pid})"

	__str__ = __repr__


# uvicorn._subprocess.get_subprocess
def get_subprocess(
	uvicorn_config: Config,
	target: Callable[..., None],
	sockets: list[socket.socket],
) -> SpawnProcess:
	stdin_fileno: Optional[int]
	try:
		stdin_fileno = sys.stdin.fileno()
	except OSError:
		stdin_fileno = None

	kwargs = {
		"uvicorn_config": uvicorn_config,
		"opsiconfd_config": config.items(),
		"target": target,
		"sockets": sockets,
		"stdin_fileno": stdin_fileno,
	}

	return spawn.Process(target=subprocess_started, kwargs=kwargs)


# uvicorn._subprocess.subprocess_started
def subprocess_started(
	uvicorn_config: Config,
	opsiconfd_config: dict[str, Any],
	target: Callable[..., None],
	sockets: list[socket.socket],
	stdin_fileno: int | None,
) -> None:
	# Re-open stdin.
	if stdin_fileno is not None:
		sys.stdin = os.fdopen(stdin_fileno)

	config.set_items(opsiconfd_config)

	# Logging needs to be setup again for each child.
	uvicorn_config.configure_logging()

	# Now we can call into `Server.run(sockets=sockets)`
	target(sockets=sockets)


class Worker(WorkerInfo, UvicornServer):
	_instance = None

	def __init__(self, node_name: str, worker_num: int) -> None:
		WorkerInfo.__init__(self, node_name, worker_num, time.time())
		UvicornServer.__init__(self, get_uvicorn_config())
		self._metrics_collector: WorkerMetricsCollector | None = None
		self.process: SpawnProcess | None = None
		self.app_state = app._app_state.type
		self.connection_close_wait_timeout = 10.0

	def start_server_process(self, sockets: list[socket.socket]) -> None:
		# Process will be spawned and will not inherit global variables from parent process
		self.process = get_subprocess(uvicorn_config=self.config, target=self.run, sockets=sockets)
		self.process.start()
		if not self.process.pid:
			raise RuntimeError("Failed to start server process")
		self.pid = self.process.pid

	@classmethod
	def get_instance(cls) -> Worker:
		if not Worker._instance:
			raise RuntimeError("Failed to get worker instance")
		return Worker._instance

	@property
	def metrics_collector(self) -> WorkerMetricsCollector:
		if not self._metrics_collector:
			self._metrics_collector = WorkerMetricsCollector(self)
		return self._metrics_collector

	def handle_asyncio_exception(self, loop: asyncio.AbstractEventLoop, context: dict) -> None:
		logger.error(
			"Unhandled exception in worker %s asyncio loop '%s': %s", self, loop, context.get("message"), exc_info=context.get("exception")
		)

	async def memory_cleanup_task(self) -> None:
		while not self.should_exit:
			for _ in range(120):
				if self.should_exit:
					return
				await asyncio_sleep(1)
			memory_cleanup()

	async def redis_disconnect_task(self) -> None:
		while not self.should_exit:
			for _ in range(1):
				if self.should_exit:
					return
				await asyncio_sleep(1)
			# Disconnect idle redis connections in all redis pools of the worker
			await pool_disconnect_connections(inuse_connections=False)

	async def state_refresh_task(self) -> None:
		while not self.should_exit:
			for _ in range(int(self.redis_state_key_expire / 2)):
				if self.should_exit:
					return
				await asyncio_sleep(1)
			redis = await async_redis_client()
			await redis.expire(self.redis_state_key, self.redis_state_key_expire)

	async def store_state_in_redis(self) -> None:
		redis = await async_redis_client()
		await redis.hset(
			self.redis_state_key,
			mapping={"pid": self.pid, "node_name": self.node_name, "worker_num": self.worker_num, "app_state": self.app_state},
		)
		await redis.expire(self.redis_state_key, self.redis_state_key_expire)

	def _run(self, sockets: Optional[list[socket.socket]] = None) -> None:
		self.pid = os.getpid()
		Worker._instance = self
		init_logging(log_mode=config.log_mode, is_worker=True)
		logger.notice("%s started", self)

		patch_popen()
		configure_warnings()

		logger.info("Setting garbage collector thresholds: %s", GC_THRESHOLDS)
		gc.set_threshold(*GC_THRESHOLDS)

		self._metrics_collector = WorkerMetricsCollector(self)

		super().run(sockets=sockets)

	def run(self, sockets: Optional[list[socket.socket]] = None) -> None:
		try:
			self._run(sockets)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("%s terminated with error: %s", self, err, exc_info=True)
		shutdown_logging()

	async def serve(self, sockets: Optional[list[socket.socket]] = None) -> None:
		loop = asyncio.get_running_loop()
		loop.set_debug("asyncio" in config.debug_options)
		init_pool_executor(loop)
		loop.set_exception_handler(self.handle_asyncio_exception)

		await self.store_state_in_redis()

		app.register_app_state_handler(self.on_app_state_change)
		asyncio_create_task(self.memory_cleanup_task())
		# Disabling for now because it sometimes causes errors like:
		# RuntimeError: unable to perform operation on <TCPTransport closed=True reading=False 0x555b11618060>; the handler is closed
		# asyncio_create_task(self.redis_disconnect_task())
		asyncio_create_task(self.metrics_collector.main_loop())
		asyncio_create_task(self.state_refresh_task())

		try:
			await super().serve(sockets=sockets)
		finally:
			redis = await async_redis_client()
			await redis.delete(self.redis_state_key)

	def get_connection_count(self) -> int:
		return len(self.server_state.connections)

	async def close_connections(  # pylint: disable=too-many-branches
		self, address_exceptions: list[str] | None = None, wait: bool = True
	) -> None:
		address_exceptions = address_exceptions or []
		logger.info("Closing connections, address exceptions: %s", address_exceptions)
		keep_connections = set()
		for connection in self.server_state.connections:
			skip = False
			if address_exceptions:
				client = connection.client
				if client:
					client_ip = client[0]
					for network in address_exceptions:
						if ip_address_in_network(client_ip, network):
							logger.info("Keeping excluded connection %s", connection)
							keep_connections.add(connection)
							skip = True
							break
			if not skip:
				if logger.isEnabledFor(DEBUG):
					logger.debug("Closing connection: %s", self.get_connection_info(connection))
				connection.shutdown()

		if not wait:
			return

		# Wait for existing connections to finish sending responses.
		if self.server_state.connections and not self.force_exit:
			logger.info(
				"Waiting for %d connections to close (timeout=%0.2f seconds)",
				len(self.server_state.connections) - len(keep_connections),
				self.connection_close_wait_timeout,
			)
			if logger.isEnabledFor(DEBUG):
				for connection in self.server_state.connections:
					if connection not in keep_connections:
						logger.debug("Waiting for connection: %s", self.get_connection_info(connection))

			start = time.time()
			while not self.force_exit:
				if not self.server_state.connections:
					break

				if keep_connections:
					wait_done = True
					for con in self.server_state.connections:
						if con not in keep_connections:
							wait_done = False
							break
					if wait_done:
						break

				if time.time() - start >= self.connection_close_wait_timeout:
					logger.notice("Timed out while waiting for connections to close")
					for connection in self.server_state.connections:
						logger.notice("Connection was not closed in time: %s", self.get_connection_info(connection))
					break

				await asyncio.sleep(0.5)

		if keep_connections:
			logger.info("All except %d connections closed", len(keep_connections))
		else:
			logger.info("All connections closed")

	def get_connection_info(self, connection: H11Protocol | HttpToolsProtocol | WSProtocol | WebSocketProtocol) -> str:
		info = ""
		client = connection.client
		if client:
			info = f"{client[0]}:{client[1]}"
		headers = getattr(connection, "headers", None)
		if headers:
			for name, val in headers:
				if name.lower() == b"user-agent":
					info = f"{info} - {val.decode('utf-8', errors='ignore')}"
					break
		scope = connection.scope
		if connection.scope:
			method = str(scope.get("method"))
			info = f'{info} - {method + " " if method else ""}{scope.get("path", "")}'
		return f"{connection.__class__.__name__}({info})"

	async def shutdown(self, sockets: Optional[list[socket.socket]] = None) -> None:
		logger.info("Shutting down")
		# Stop accepting new connections.
		logger.info("Stop accepting new connections")
		if hasattr(self, "servers"):
			for server in self.servers:
				server.close()
			for sock in sockets or []:
				sock.close()
			for server in self.servers:
				await server.wait_closed()

		# Request shutdown on all existing connections.
		await self.close_connections(wait=not self.force_exit)
		await asyncio.sleep(0.1)

		if self._metrics_collector:
			self._metrics_collector.stop()

		# Wait for existing tasks to complete.
		if self.server_state.tasks and not self.force_exit:
			logger.info("Waiting for background tasks to complete")
			while self.server_state.tasks and not self.force_exit:
				await asyncio.sleep(0.1)

		# Send the lifespan shutdown event, and wait for application shutdown.
		if not self.force_exit:
			await self.lifespan.shutdown()

	def install_signal_handlers(self) -> None:
		loop = asyncio.get_event_loop()
		loop.add_signal_handler(SIGHUP, self.handle_sighup)
		super().install_signal_handlers()

	def handle_sighup(self) -> None:
		logger.notice("%s reloading", self)
		config.reload()
		for key, value in get_uvicorn_config().__dict__.items():
			# Do not replace the whole config object, because uvicorn
			# server adds additional keys like "encoded_headers" on start
			if value is not None:
				setattr(self.config, key, value)
		init_logging(log_mode=config.log_mode, is_worker=True)
		memory_cleanup()
		get_protected_backend().reload_config()
		get_unprotected_backend().reload_config()
		AddonManager().reload_addons()

	async def on_app_state_change(self, app_state: AppState) -> None:
		logger.notice("%s handling %s", self, app_state)
		if app_state.accomplished:
			return
		if isinstance(app_state, MaintenanceState):
			logger.info("%s closing all connections", self)
			await self.close_connections(address_exceptions=app_state.address_exceptions, wait=True)
		self.app_state = app_state.type
		await self.store_state_in_redis()
