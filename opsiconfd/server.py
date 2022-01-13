# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.server
"""

import os
import time
import threading
import signal
import socket
import base64
from typing import List
from multiprocessing import Process
import psutil

try:
	# python3-pycryptodome installs into Cryptodome
	from Cryptodome.Hash import MD5  # type: ignore
	from Cryptodome.Signature import pkcs1_15  # type: ignore
except ImportError:
	# PyCryptodome from pypi installs into Crypto
	from Crypto.Hash import MD5
	from Crypto.Signature import pkcs1_15

from uvicorn.subprocess import get_subprocess
from uvicorn.config import Config
from uvicorn.server import Server as UvicornServer

from OPSI.Util import getPublicKey

from .config import config
from .logging import logger, init_logging
from .utils import get_redis_connection, retry_redis_call
from .backend import get_backend
from . import ssl
from . import __version__


class Supervisor:  # pylint: disable=too-many-instance-attributes,too-many-branches
	def __init__(self, server: UvicornServer):
		self.server = server
		self.socket = None
		self.node_name = config.node_name
		self.workers = []
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
	def uvicorn_config(self):
		return self.server.config

	def bind_socket(self):
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

	def run(self):
		self.bind_socket()
		self.adjust_worker_count()
		while not self.should_stop:
			for _num in range(10):
				if self.should_stop:
					break
				time.sleep(1)

			auto_restart = []
			with self.worker_update_lock:
				for worker in self.workers:
					if self.should_restart_workers:
						auto_restart.append(worker.worker_num)

					elif worker.is_alive():
						if self.worker_restart_time > 0:
							alive = time.time() - worker.create_time
							if alive >= self.worker_restart_time:
								logger.notice(
									"Worker %d (pid %d) has been running for %s seconds",
									worker.worker_num, worker.pid, alive
								)
								auto_restart.append(worker.worker_num)

						if self.worker_restart_mem > 0:
							now = time.time()
							mem = psutil.Process(worker.pid).memory_info().rss
							if mem >= self.worker_restart_mem:
								if not hasattr(worker, 'max_mem_exceeded_since'):
									worker.max_mem_exceeded_since = now
								if now - worker.max_mem_exceeded_since >= self.worker_restart_mem_interval:
									logger.notice(
										"Worker %d (pid %d) is using more than %0.2f MB of memory "
										"(currently %0.2f MB) since %d seconds",
										worker.worker_num, worker.pid,
										self.worker_restart_mem / 1000000, mem / 1000000,
										now - worker.max_mem_exceeded_since
									)
									auto_restart.append(worker.worker_num)
							elif hasattr(worker, 'max_mem_exceeded_since'):
								delattr(worker, 'max_mem_exceeded_since')

					elif not getattr(worker, "marked_as_vanished", False):
						# Worker crashed / killed
						if self.startup:
							logger.critical("Failed to start worker %d (pid %d)", worker.worker_num, worker.pid)
							self.stop(force=True)
							break

						logger.warning("Worker %d (pid %d) vanished", worker.worker_num, worker.pid)
						worker.marked_as_vanished = True
						if self.restart_vanished_workers:
							auto_restart.append(worker.worker_num)

			for worker_num in auto_restart:
				if self.should_stop:
					break
				self.restart_worker(worker_num)
				for _snum in range(5):
					if self.should_stop:
						break
					time.sleep(1)

			self.update_worker_registry()

			self.startup = False
			self.should_restart_workers = False

		while self.workers:
			time.sleep(1)

	def reload(self):
		for worker in self.workers:
			os.kill(worker.pid, signal.SIGHUP)

		self.adjust_worker_count()

	def stop(self, force=False):
		self.should_stop = True
		logger.notice("Stopping all workers (force=%s)", force)
		self.stop_worker([worker.pid for worker in self.workers], force=force)
		logger.info("All workers stopped")

	def get_worker(self, pid: int) -> Process:
		for worker in self.workers:
			if worker.pid == pid:
				return worker
		return None

	def start_worker(self, worker_num: int):
		# Put CA key into environment for worker processes
		if config.ssl_ca_key in ssl.KEY_CACHE:
			os.putenv("OPSICONFD_WORKER_OPSI_SSL_CA_KEY", ssl.KEY_CACHE[config.ssl_ca_key])
		os.putenv("OPSICONFD_WORKER_WORKER_NUM", str(worker_num))

		process = get_subprocess(
			config=self.uvicorn_config, target=self.server.run, sockets=[self.socket]
		)
		process.start()
		process.create_time = time.time()
		process.worker_num = worker_num

		logger.notice("New worker %d (pid %d) started", worker_num, process.pid)
		while len(self.workers) < worker_num:
			self.workers.append(None)
		self.workers[worker_num - 1] = process

		if config.ssl_ca_key in ssl.KEY_CACHE:
			os.unsetenv("OPSICONFD_WORKER_OPSI_SSL_CA_KEY")
		os.unsetenv("OPSICONFD_WORKER_WORKER_NUM")

	def stop_worker(self, pids: List[int], force: bool = False, wait: bool = True, remove_worker: bool = True):
		workers = []
		for pid in pids:
			worker = self.get_worker(pid)
			if worker:
				workers.append(worker)
				if worker.is_alive():
					logger.notice("Stopping worker %d (pid %d) (force=%s)", worker.worker_num, worker.pid, force)
					worker.terminate()
					if force:
						# Send twice, uvicorn worker will not wait for connectons to close.
						time.sleep(1)
						worker.terminate()

		if wait:
			start_time = time.time()
			while True:
				any_alive = False
				diff = time.time() - start_time
				for worker in workers:
					if not worker.is_alive():
						continue
					any_alive = True
					if diff < self.worker_stop_timeout:
						continue
					logger.warning(
						"Timed out after %d seconds while waiting for worker %s to stop, forcing worker to stop",
						diff, worker.pid
					)
					if diff > self.worker_stop_timeout + 5:
						worker.kill()
					else:
						worker.terminate()
				if not any_alive:
					break
				time.sleep(1)

		if remove_worker:
			for worker in workers:
				if worker in self.workers:
					self.workers.remove(worker)

	def restart_worker(self, worker_num: int):
		with self.worker_update_lock:
			worker = self.workers[worker_num - 1]
			logger.notice("Restarting worker %d (pid %d)", worker_num, worker.pid)
			if worker.is_alive():
				self.stop_worker([worker.pid], remove_worker=False)
			self.start_worker(worker_num=worker_num)

	def adjust_worker_count(self):
		with self.worker_update_lock:
			while len(self.workers) < self.uvicorn_config.workers:
				self.start_worker(worker_num=len(self.workers) + 1)
			while len(self.workers) > self.uvicorn_config.workers:
				self.stop_worker([self.workers[-1].pid])

	@retry_redis_call
	def update_worker_registry(self):
		redis = get_redis_connection(config.redis_internal_url)
		with self.worker_update_lock:
			for worker in self.workers:
				redis_key = f"opsiconfd:worker_registry:{self.node_name}:{worker.worker_num}"
				redis.hmset(redis_key, {
					"worker_pid": worker.pid,
					"node_name": self.node_name,
					"worker_num": worker.worker_num
				})
				redis.expire(redis_key, 60)

			for redis_key in redis.scan_iter(f"opsiconfd:worker_registry:{self.node_name}:*"):
				redis_key = redis_key.decode("utf-8")
				try:
					worker_num = int(redis_key.split(':')[-1])
				except IndexError:
					worker_num = -1
				if worker_num == -1 or worker_num > len(self.workers):
					# Delete obsolete worker entry
					redis.delete(redis_key)


class Server:
	def __init__(self) -> None:
		self.uvicorn_config = None
		self.uvicorn_server = None
		self.supervisor = None

	def run(self):
		self.check_modules()
		self.create_uvicorn_config()

		logger.notice("Starting server")
		self.uvicorn_server = UvicornServer(config=self.uvicorn_config)

		init_logging(config.log_mode)

		self.supervisor = Supervisor(server=self.uvicorn_server)
		self.supervisor.run()

		logger.notice("Server exited")

	def reload(self):
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

	def stop(self, force=False):
		logger.notice("Stopping server")
		if self.supervisor:
			logger.info("Stopping supervisor")
			self.supervisor.stop(force)
		elif self.uvicorn_server:
			logger.info("Stopping single uvicorn server")
			self.uvicorn_server.should_exit = True
			if force:
				self.uvicorn_server.force_exit = True

	def restart_workers(self):
		if self.supervisor:
			self.supervisor.should_restart_workers = True

	def create_uvicorn_config(self):
		options = {
			"interface": "asgi3",
			"http": "h11",  # "httptools"
			"host": config.interface,
			"port": config.port,
			"workers": config.workers,
			"log_config": None,
			"debug": config.debug,
			"headers": [
				["Server", f"opsiconfd {__version__} (uvicorn)"]
			]
		}
		# if config.workers == 1 and config.interface == "::":
		#   options["host"] = ["::", "0.0.0.0"]
		if config.ssl_server_key and config.ssl_server_cert:
			options["ssl_keyfile"] = config.ssl_server_key
			options["ssl_keyfile_password"] = config.ssl_server_key_passphrase
			options["ssl_certfile"] = config.ssl_server_cert
			options["ssl_ciphers"] = config.ssl_ciphers

		self.uvicorn_config = Config("opsiconfd.application:app", **options)

	def check_modules(self):  # pylint: disable=no-self-use,too-many-statements,too-many-branches
		if config.workers == 1:
			return
		num_workers = 1
		backend_info = get_backend().backend_info()
		modules = backend_info['modules']
		helpermodules = backend_info['realmodules']

		if not all(key in modules for key in ('expires', 'customer')):
			logger.error(
				"Missing important information about modules. Probably no modules file installed. Limiting to %d workers.",
				num_workers
			)
		elif not modules.get('customer'):
			logger.error("No customer in modules file. Limiting to %d workers.", num_workers)
		elif not modules.get('valid'):
			logger.error("Modules file invalid. Limiting to %d workers.", num_workers)
		elif (
			modules.get('expires', '') != 'never' and
			time.mktime(time.strptime(modules.get('expires', '2000-01-01'), "%Y-%m-%d")) - time.time() <= 0
		):
			logger.error("Modules file expired. Limiting to %d workers.", num_workers)
		else:
			logger.info("Verifying modules file signature")
			public_key = getPublicKey(
				data=base64.decodebytes(
					b"AAAAB3NzaC1yc2EAAAADAQABAAABAQCAD/I79Jd0eKwwfuVwh5B2z+S8aV0C5suItJa18RrYip+d4P0ogzqoCfOoVWtDo"
					b"jY96FDYv+2d73LsoOckHCnuh55GA0mtuVMWdXNZIE8Avt/RzbEoYGo/H0weuga7I8PuQNC/nyS8w3W8TH4pt+ZCjZZoX8"
					b"S+IizWCYwfqYoYTMLgB0i+6TCAfJj3mNgCrDZkQ24+rOFS4a8RrjamEz/b81noWl9IntllK1hySkR+LbulfTGALHgHkDU"
					b"lk0OSu+zBPw/hcDSOMiDQvvHfmR4quGyLPbQ2FOVm1TzE0bQPR+Bhx4V8Eo2kNYstG2eJELrz7J1TJI0rCjpB+FQjYPsP"
				)
			)
			data = ""
			mks = list(modules.keys())
			mks.sort()
			for module in mks:
				if module in ("valid", "signature"):
					continue
				if module in helpermodules:
					val = helpermodules[module]
					if int(val) > 0:
						modules[module] = True
				else:
					val = modules[module]
					if isinstance(val, bool):
						val = "yes" if val else "no"
				data += f"{module.lower().strip()} = {val}\r\n"

			verified = False
			if modules["signature"].startswith("{"):
				s_bytes = int(modules['signature'].split("}", 1)[-1]).to_bytes(256, "big")
				try:
					pkcs1_15.new(public_key).verify(MD5.new(data.encode()), s_bytes)
					verified = True
				except ValueError:
					# Invalid signature
					pass
			else:
				h_int = int.from_bytes(MD5.new(data.encode()).digest(), "big")
				s_int = public_key._encrypt(int(modules["signature"]))  # pylint: disable=protected-access
				verified = h_int == s_int

			if not verified:
				logger.error("Modules file invalid. Limiting to %d workers.", num_workers)
			else:
				logger.debug("Modules file signature verified (customer: %s)", modules.get('customer'))

				if modules.get("scalability1"):
					num_workers = config.workers
				else:
					logger.error("scalability1 missing in modules file. Limiting to %d workers.", num_workers)

		config.workers = num_workers
