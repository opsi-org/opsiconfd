# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.server
"""

import os
import signal
import socket
import threading
import time
from multiprocessing.context import SpawnProcess
from typing import List, Optional

import psutil
from uvicorn._subprocess import get_subprocess  # type: ignore[import]
from uvicorn.config import Config  # type: ignore[import]
from uvicorn.server import Server as UvicornServer  # type: ignore[import]

from . import __version__, ssl
from .backend import get_backend
from .config import config
from .logging import init_logging, logger
from .utils import get_redis_connection, retry_redis_call
from .ssl import opsi_ca_is_self_signed


class WorkerProcess:  # pylint: disable=too-few-public-methods
	def __init__(self, process: SpawnProcess, worker_num: int) -> None:
		self.process = process
		self.worker_num = worker_num
		self.create_time = time.time()

	@property
	def pid(self) -> int:
		if not self.process.pid:
			raise RuntimeError(f"Failed to get pid of {self.process}")
		return self.process.pid


class Supervisor:  # pylint: disable=too-many-instance-attributes,too-many-branches
	def __init__(self, server: UvicornServer):
		self.server = server
		self.socket: socket.socket | None = None
		self.node_name = config.node_name
		self.workers: List[WorkerProcess] = []
		self.worker_stop_timeout = config.worker_stop_timeout
		self.worker_restart_time = 0
		self.worker_restart_mem = config.restart_worker_mem * 1000000
		self.worker_restart_mem_interval = 3600
		self.restart_vanished_workers = True
		self.worker_update_lock = threading.Lock()
		self.should_restart_workers = False
		self.should_stop = False
		self.pid = os.getpid()
		self.startup = True

	@property
	def uvicorn_config(self) -> Config:
		return self.server.config

	def bind_socket(self) -> None:
		# This is only used for multi worker configs
		ipv6 = ":" in self.uvicorn_config.host
		self.socket = socket.socket(family=socket.AF_INET6 if ipv6 else socket.AF_INET)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			self.socket.bind((self.uvicorn_config.host, self.uvicorn_config.port))
		except OSError as exc:
			logger.error(exc)
			raise
		self.socket.set_inheritable(True)

	def run(self) -> None:
		self.bind_socket()
		self.adjust_worker_count()
		while not self.should_stop:
			for _num in range(10):
				if self.should_stop:
					break
				time.sleep(1)  # pylint: disable=dotted-import-in-loop

			auto_restart = []
			with self.worker_update_lock:
				for worker in self.workers:
					if self.should_restart_workers:
						auto_restart.append(worker.worker_num)

					elif worker.process.is_alive():
						if self.worker_restart_time > 0:
							alive = time.time() - worker.create_time  # pylint: disable=dotted-import-in-loop
							if alive >= self.worker_restart_time:
								logger.notice("Worker %d (pid %d) has been running for %s seconds", worker.worker_num, worker.pid, alive)
								auto_restart.append(worker.worker_num)

						if self.worker_restart_mem > 0:
							now = time.time()  # pylint: disable=dotted-import-in-loop
							mem = psutil.Process(worker.pid).memory_info().rss  # pylint: disable=dotted-import-in-loop
							if mem >= self.worker_restart_mem:
								if not hasattr(worker, "max_mem_exceeded_since"):
									setattr(worker, "max_mem_exceeded_since", now)
								if now - getattr(worker, "max_mem_exceeded_since") >= self.worker_restart_mem_interval:
									logger.notice(
										"Worker %d (pid %d) is using more than %0.2f MB of memory (currently %0.2f MB) since %d seconds",
										worker.worker_num,
										worker.pid,
										self.worker_restart_mem / 1000000,
										mem / 1000000,
										now - getattr(worker, "max_mem_exceeded_since"),
									)
									auto_restart.append(worker.worker_num)
							elif hasattr(worker, "max_mem_exceeded_since"):
								delattr(worker, "max_mem_exceeded_since")

					elif not getattr(worker, "marked_as_vanished", False):
						# Worker crashed / killed
						if self.startup:
							logger.critical("Failed to start worker %d (pid %d)", worker.worker_num, worker.pid)
							self.stop(force=True)
							break

						logger.warning("Worker %d (pid %d) vanished", worker.worker_num, worker.pid)
						setattr(worker, "marked_as_vanished", True)
						if self.restart_vanished_workers:
							auto_restart.append(worker.worker_num)

			for worker_num in auto_restart:
				if self.should_stop:
					break
				self.restart_worker(worker_num)
				for _snum in range(5):
					if self.should_stop:
						break
					time.sleep(1)  # pylint: disable=dotted-import-in-loop

			self.update_worker_registry()

			self.startup = False
			self.should_restart_workers = False

		while self.workers:
			time.sleep(1)  # pylint: disable=dotted-import-in-loop

	def reload(self) -> None:
		for worker in self.workers:
			os.kill(worker.pid, signal.SIGHUP)  # pylint: disable=dotted-import-in-loop

		self.adjust_worker_count()

	def stop(self, force: bool = False) -> None:
		self.should_stop = True
		logger.notice("Stopping all workers (force=%s)", force)
		self.stop_worker([worker.pid for worker in self.workers], force=force)
		logger.info("All workers stopped")

	def get_worker(self, pid: int) -> Optional[WorkerProcess]:
		for worker in self.workers:
			if worker.pid == pid:
				return worker
		return None

	def start_worker(self, worker_num: int) -> None:
		# Put CA key into environment for worker processes

		if config.ssl_ca_key in ssl.KEY_CACHE:
			os.putenv("OPSICONFD_WORKER_OPSI_SSL_CA_KEY", ssl.KEY_CACHE[config.ssl_ca_key])
		os.putenv("OPSICONFD_WORKER_WORKER_NUM", str(worker_num))
		os.putenv("OPSICONFD_CONFIG_FILE", config.config_file)

		assert self.socket
		worker = WorkerProcess(get_subprocess(config=self.uvicorn_config, target=self.server.run, sockets=[self.socket]), worker_num)
		worker.process.start()

		logger.notice("New worker %d (pid %d) started", worker_num, worker.pid)
		while len(self.workers) < worker_num:
			self.workers.append(None)  # type: ignore[arg-type] # pylint: disable=loop-invariant-statement
		self.workers[worker_num - 1] = worker

		if config.ssl_ca_key in ssl.KEY_CACHE:
			os.unsetenv("OPSICONFD_WORKER_OPSI_SSL_CA_KEY")
		os.unsetenv("OPSICONFD_WORKER_WORKER_NUM")

	def stop_worker(self, pids: List[int], force: bool = False, wait: bool = True, remove_worker: bool = True) -> None:
		workers = []
		for pid in pids:
			worker = self.get_worker(pid)
			if worker:
				workers.append(worker)
				if worker.process.is_alive():
					logger.notice("Stopping worker %d (pid %d) (force=%s)", worker.worker_num, worker.pid, force)
					worker.process.terminate()
					if force:
						# Send twice, uvicorn worker will not wait for connectons to close.
						time.sleep(1)  # pylint: disable=dotted-import-in-loop
						worker.process.terminate()

		if wait:
			start_time = time.time()
			while True:
				any_alive = False
				diff = time.time() - start_time  # pylint: disable=dotted-import-in-loop
				for worker in workers:
					if not worker.process.is_alive():
						continue
					any_alive = True
					if diff < self.worker_stop_timeout:  # pylint: disable=loop-invariant-statement
						continue
					logger.warning(
						"Timed out after %d seconds while waiting for worker %s to stop, forcing worker to stop", diff, worker.pid
					)
					if diff > self.worker_stop_timeout + 5:  # pylint: disable=loop-invariant-statement
						worker.process.kill()
					else:
						worker.process.terminate()
				if not any_alive:
					break
				time.sleep(1)  # pylint: disable=dotted-import-in-loop

		if remove_worker:
			for worker in workers:
				if worker in self.workers:
					self.workers.remove(worker)

	def restart_worker(self, worker_num: int) -> None:
		with self.worker_update_lock:
			worker = self.workers[worker_num - 1]
			logger.notice("Restarting worker %d (pid %d)", worker_num, worker.pid)
			if worker.process.is_alive():
				self.stop_worker([worker.pid], remove_worker=False)
			self.start_worker(worker_num=worker_num)

	def adjust_worker_count(self) -> None:
		with self.worker_update_lock:
			while len(self.workers) < self.uvicorn_config.workers:
				self.start_worker(worker_num=len(self.workers) + 1)
			while len(self.workers) > self.uvicorn_config.workers:
				self.stop_worker([self.workers[-1].pid])

	@retry_redis_call
	def update_worker_registry(self) -> None:
		redis = get_redis_connection(config.redis_internal_url)
		with self.worker_update_lock:
			for worker in self.workers:
				redis_key = f"opsiconfd:worker_registry:{self.node_name}:{worker.worker_num}"
				redis.hset(
					redis_key,
					key=None,
					value=None,
					mapping={"worker_pid": worker.pid, "node_name": self.node_name, "worker_num": worker.worker_num},
				)
				redis.expire(redis_key, 60)

			for redis_key_b in redis.scan_iter(f"opsiconfd:worker_registry:{self.node_name}:*"):  # pylint: disable=loop-invariant-statement
				redis_key = redis_key_b.decode("utf-8")
				try:  # pylint: disable=loop-try-except-usage
					worker_num = int(redis_key.split(":")[-1])
				except IndexError:
					worker_num = -1
				if worker_num == -1 or worker_num > len(self.workers):
					# Delete obsolete worker entry
					redis.delete(redis_key)


class Server:
	def __init__(self) -> None:
		self.uvicorn_config: Config | None = None
		self.uvicorn_server: UvicornServer | None = None
		self.supervisor: Supervisor | None = None

	def run(self) -> None:
		self.check_modules()
		self.create_uvicorn_config()

		logger.notice("Starting server")
		assert self.uvicorn_config
		self.uvicorn_server = UvicornServer(config=self.uvicorn_config)

		init_logging(config.log_mode)

		self.supervisor = Supervisor(server=self.uvicorn_server)
		self.supervisor.run()

		logger.notice("Server exited")

	def reload(self) -> None:
		self.check_modules()
		self.create_uvicorn_config()
		if self.uvicorn_server:
			for key, value in self.uvicorn_config.__dict__.items():
				# Do not replace the whole config object, because uvicorn
				# server adds additional keys like "encoded_headers" on start
				if value is not None:
					setattr(self.uvicorn_server.config, key, value)
		if self.supervisor:
			self.supervisor.reload()

	def stop(self, force: bool = False) -> None:
		logger.notice("Stopping server")
		if self.supervisor:
			logger.info("Stopping supervisor")
			self.supervisor.stop(force)
		elif self.uvicorn_server:
			logger.info("Stopping single uvicorn server")
			self.uvicorn_server.should_exit = True
			if force:
				self.uvicorn_server.force_exit = True

	def restart_workers(self) -> None:
		if self.supervisor:
			self.supervisor.should_restart_workers = True

	def create_uvicorn_config(self) -> None:
		options = {
			"interface": "asgi3",
			"http": "h11",  # "httptools"
			"host": config.interface,
			"port": config.port,
			"workers": config.workers,
			"log_config": None,
			"headers": [["Server", f"opsiconfd {__version__} (uvicorn)"]],
			"ws_ping_interval": 15,
			"ws_ping_timeout": 10,
		}
		if config.ssl_server_key and config.ssl_server_cert:
			options["ssl_keyfile"] = config.ssl_server_key
			options["ssl_keyfile_password"] = config.ssl_server_key_passphrase
			options["ssl_certfile"] = config.ssl_server_cert
			options["ssl_ciphers"] = config.ssl_ciphers
			if not opsi_ca_is_self_signed():
				options["ssl_ca_certs"] = config.ssl_ca_cert

		self.uvicorn_config = Config("opsiconfd.application:app", **options)

	def check_modules(self) -> None:  # pylint: disable=too-many-statements,too-many-branches
		if config.workers == 1:
			return

		if "scalability1" not in get_backend().backend_getLicensingInfo()["available_modules"]:  # pylint: disable=no-member
			config.workers = 1
			logger.error("Module 'scalability1' not licensed, limiting to %d workers.", config.workers)
