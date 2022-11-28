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
import os
import socket
import time
from asyncio import sleep as asyncio_sleep
from concurrent.futures import ThreadPoolExecutor
from multiprocessing.context import SpawnProcess
from signal import SIGHUP
from typing import List, Optional

from uvicorn._subprocess import get_subprocess  # type: ignore[import]
from uvicorn.config import Config  # type: ignore[import]
from uvicorn.server import Server as UvicornServer  # type: ignore[import]

from . import __version__
from .addon import AddonManager
from .backend import get_protected_backend
from .config import GC_THRESHOLDS, config
from .logging import init_logging, logger
from .metrics.collector import WorkerMetricsCollector


def init_pool_executor(loop: asyncio.AbstractEventLoop) -> None:
	# https://bugs.python.org/issue41699
	pool_executor = ThreadPoolExecutor(  # pylint: disable=consider-using-with
		max_workers=config.executor_workers, thread_name_prefix="worker-ThreadPoolExecutor"
	)
	loop.set_default_executor(pool_executor)


def memory_cleanup() -> None:
	gc.collect()
	ctypes.CDLL("libc.so.6").malloc_trim(0)


def uvicorn_config() -> Config:
	options = {
		"interface": "asgi3",
		"http": "h11",  # "httptools"
		"host": config.interface,
		"port": config.port,
		"workers": config.workers,
		"log_config": None,
		"headers": [["Server", f"opsiconfd {__version__} (uvicorn)"]],
		"ws_ping_interval": 15,
		"ws_ping_timeout": 10
	}
	if config.ssl_server_key and config.ssl_server_cert:
		options["ssl_keyfile"] = config.ssl_server_key
		options["ssl_keyfile_password"] = config.ssl_server_key_passphrase
		options["ssl_certfile"] = config.ssl_server_cert
		options["ssl_ciphers"] = config.ssl_ciphers
		if config.ssl_ca_cert and os.path.exists(config.ssl_ca_cert):
			options["ssl_ca_certs"] = config.ssl_ca_cert

	return Config("opsiconfd.application:app", **options)


class Worker(UvicornServer):
	_instance = None

	def __init__(self, worker_num: int) -> None:
		self.worker_num = worker_num
		self.create_time = time.time()
		UvicornServer.__init__(self, uvicorn_config())
		self._metrics_collector: WorkerMetricsCollector | None = None
		self.process: SpawnProcess | None = None

	def start_server_process(self, sockets: List[socket.socket]) -> None:
		self.process = get_subprocess(config=self.config, target=self.run, sockets=sockets)
		self.process.start()

	@classmethod
	def get_instance(cls) -> Worker:
		if not Worker._instance:
			raise RuntimeError("Failed to get worker instance")
		return Worker._instance

	def __repr__(self) -> str:
		return f"<{self.__class__.__name__} {self.worker_num} (pid: {self.pid}>"

	__str__ = __repr__

	@property
	def pid(self) -> int:
		if not self.process or not self.process.pid:
			return os.getpid()
		return self.process.pid

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
					break
				await asyncio_sleep(1)
			memory_cleanup()

	def run(self, sockets: Optional[List[socket.socket]] = None) -> None:
		Worker._instance = self
		init_logging(log_mode=config.log_mode, is_worker=True)
		logger.notice("Startup worker %d (pid %s)", self.worker_num, self.pid)

		logger.info("Setting garbage collector thresholds: %s", GC_THRESHOLDS)
		gc.set_threshold(*GC_THRESHOLDS)

		self._metrics_collector = WorkerMetricsCollector(self)
		super().run(sockets=sockets)

	async def serve(self, sockets: Optional[List[socket.socket]] = None) -> None:
		loop = asyncio.get_running_loop()
		loop.set_debug(config.debug)
		init_pool_executor(loop)
		loop.set_exception_handler(self.handle_asyncio_exception)

		asyncio.create_task(self.memory_cleanup_task())
		asyncio.create_task(self.metrics_collector.main_loop())

		await super().serve(sockets=sockets)

	async def shutdown(self, sockets: Optional[List[socket.socket]] = None) -> None:
		await super().shutdown(sockets=sockets)

	def install_signal_handlers(self) -> None:
		loop = asyncio.get_event_loop()
		loop.add_signal_handler(SIGHUP, self.handle_sighup)
		super().install_signal_handlers()

	def handle_sighup(self) -> None:
		logger.notice("Worker process %d (pid %d) reloading", self.worker_num, self.pid)
		config.reload()
		for key, value in uvicorn_config().__dict__.items():
			# Do not replace the whole config object, because uvicorn
			# server adds additional keys like "encoded_headers" on start
			if value is not None:
				setattr(self.config, key, value)
		init_logging(log_mode=config.log_mode, is_worker=True)
		memory_cleanup()
		get_protected_backend().reload_config()
		AddonManager().reload_addons()
