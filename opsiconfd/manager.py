# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
manager
"""

import asyncio
import os
import signal
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock, Thread
from types import FrameType
from typing import Optional

import psutil
from opsicommon.client.opsiservice import MessagebusListener, ServiceClient
from opsicommon.messagebus import CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	ChannelSubscriptionEventMessage,
	Message,
	TraceRequestMessage,
	TraceResponseMessage,
)
from opsicommon.messagebus.message import timestamp as mb_timestamp
from starlette.concurrency import run_in_threadpool

from opsiconfd.application import MaintenanceState, NormalState, ShutdownState, app
from opsiconfd.application.filetransfer import cleanup_file_storage
from opsiconfd.backend import get_service_client, get_unprotected_backend
from opsiconfd.backend.rpc.cache import rpc_cache_clear
from opsiconfd.config import MANAGER_THREAD_POOL_WORKERS, config, get_server_role
from opsiconfd.logging import init_logging, logger
from opsiconfd.messagebus.redis import messagebus_cleanup
from opsiconfd.metrics.collector import ManagerMetricsCollector
from opsiconfd.redis import async_get_redis_info, async_redis_client, redis_client
from opsiconfd.ssl import setup_ssl
from opsiconfd.utils import Singleton, asyncio_create_task, log_config
from opsiconfd.worker import Worker, WorkerInfo, WorkerState
from opsiconfd.zeroconf import register_opsi_services, unregister_opsi_services


class WorkerManager:
	def __init__(self) -> None:
		self.socket: socket.socket | None = None
		self.node_name = config.node_name
		self.workers: dict[str, WorkerInfo] = {}
		self.worker_stop_timeout = config.worker_stop_timeout
		self.worker_restart_time = 0
		self.worker_restart_mem = config.restart_worker_mem * 1000000
		self.worker_restart_mem_interval = 3600
		self.worker_check_interval = 10.0
		self.worker_restart_gap = 5.0
		self.startup_time = 15.0
		self.restart_vanished_workers = True
		self.worker_update_lock = Lock()
		self.should_restart_workers = False
		self.should_stop = Event()
		self.pid = os.getpid()
		self.startup_completed = Event()

	def restart_workers(self, wait: bool = False) -> None:
		pids = [w.pid for w in self.workers.values()]
		self.should_restart_workers = True
		if wait:
			while True:
				restarted = True
				for worker in self.workers.values():
					if worker.pid in pids:
						restarted = False
						break
				if restarted:
					break
				time.sleep(0.5)

	def check_modules(self) -> None:
		if config.workers == 1:
			return

		if "scalability1" not in get_unprotected_backend().available_modules:
			config.workers = 1
			logger.error("Module 'scalability1' not licensed, limiting to %d workers.", config.workers)

	def bind_socket(self) -> None:
		ipv6 = ":" in config.interface
		self.socket = socket.socket(family=socket.AF_INET6 if ipv6 else socket.AF_INET)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			self.socket.bind((config.interface, config.port))
		except OSError as exc:
			logger.error(exc)
			raise
		self.socket.set_inheritable(True)

	def get_workers(self) -> list[Worker]:
		return [w for w in self.workers.values() if isinstance(w, Worker)]

	def get_worker_infos(self) -> list[WorkerInfo]:
		return list(self.workers.values())

	def init_logging(self) -> None:
		init_logging(config.log_mode)

	def run(self) -> None:
		logger.notice("Starting server")
		self.init_logging()
		self.check_modules()
		self.bind_socket()
		self.adjust_worker_count()
		# Wait for all worker processes to start and see if they keep running
		startup_end_time = time.time() + self.startup_time
		while True:
			worker_failed = False  # Set after a running worker was stopped again (failed)
			all_running = True
			with self.worker_update_lock:
				for worker in self.get_workers():
					if worker.process and worker.process.is_alive():
						worker.worker_state = WorkerState.RUNNING
					else:
						if all_running:
							worker_failed = True
						all_running = False

			if not worker_failed and time.time() < startup_end_time:
				if self.should_stop.wait(1.0):
					break
				continue

			if all_running:
				logger.info("Startup completed, all workers running")
				self.startup_completed.set()
				break

			failed_workers = [
				w for w in self.get_workers() if w.worker_state != WorkerState.RUNNING or (w.process and not w.process.is_alive())
			]
			logger.critical("Failed to start workers: %r", failed_workers)
			self.stop(force=True)

		while not self.should_stop.is_set():
			auto_restart = []
			with self.worker_update_lock:
				for worker in self.get_workers():
					if self.should_restart_workers:
						auto_restart.append(worker)
					elif worker.process and worker.process.is_alive():
						# Worker is running
						worker.worker_state = WorkerState.RUNNING
						if self.worker_restart_time > 0:
							alive = time.time() - worker.create_time
							if alive >= self.worker_restart_time:
								logger.notice("%s has been running for %s seconds", worker, alive)
								auto_restart.append(worker)

						if self.worker_restart_mem > 0:
							now = time.time()
							mem = psutil.Process(worker.pid).memory_info().rss
							if mem >= self.worker_restart_mem:
								if not hasattr(worker, "max_mem_exceeded_since"):
									setattr(worker, "max_mem_exceeded_since", now)
								if now - getattr(worker, "max_mem_exceeded_since") >= self.worker_restart_mem_interval:
									logger.notice(
										"%s is using more than %0.2f MB of memory (currently %0.2f MB) since %d seconds",
										worker,
										self.worker_restart_mem / 1000000,
										mem / 1000000,
										now - getattr(worker, "max_mem_exceeded_since"),
									)
									auto_restart.append(worker)
							elif hasattr(worker, "max_mem_exceeded_since"):
								delattr(worker, "max_mem_exceeded_since")
					elif worker.worker_state == WorkerState.RUNNING:
						logger.warning("%s vanished", worker)
						worker.worker_state = WorkerState.VANISHED
						if self.restart_vanished_workers:
							auto_restart.append(worker)

			for worker in auto_restart:
				if self.should_stop.is_set():
					break
				self.restart_worker(worker)
				self.should_stop.wait(self.worker_restart_gap)

			self.update_worker_state()

			self.should_restart_workers = False
			self.should_stop.wait(self.worker_check_interval)

		while self.workers:
			time.sleep(0.1)

	def reload(self) -> None:
		self.check_modules()
		for worker in self.get_workers():
			os.kill(worker.pid, signal.SIGHUP)

		self.adjust_worker_count()

	def stop(self, force: bool = False) -> None:
		self.should_stop.set()
		logger.notice("Stopping all workers (force=%s)", force)
		self.stop_worker(self.get_workers(), force=force)
		if not force:
			logger.notice("All workers stopped")

	def get_worker(self, pid: int) -> Optional[Worker]:
		for worker in self.get_workers():
			if worker.pid == pid:
				return worker
		return None

	def start_worker(self, worker: Worker | None = None) -> None:
		if not self.socket:
			raise RuntimeError("Socket not initialized")

		if not worker:
			worker_nums = sorted([w.worker_num for w in self.get_workers()])
			worker_num = worker_nums[-1] + 1 if worker_nums else 1
			worker = Worker(self.node_name, worker_num)

		worker.worker_state = WorkerState.STARTING
		worker.start_server_process([self.socket])

		logger.info("New %s started", worker)
		self.workers[worker.id] = worker

	def stop_worker(self, workers: list[Worker] | Worker, force: bool = False, wait: bool = True, remove_worker: bool = True) -> None:
		if not isinstance(workers, list):
			workers = [workers]
		for worker in workers:
			worker.worker_state = WorkerState.STOPPING
			if worker.process and worker.process.is_alive():
				logger.notice("Stopping %s (force=%s)", worker, force)
				worker.process.terminate()
				if force:
					# Send twice, uvicorn worker will not wait for connectons to close.
					time.sleep(1)
					worker.process.terminate()

		if wait:
			start_time = time.time()
			while True:
				any_alive = False
				diff = time.time() - start_time
				for worker in workers:
					if not worker.process or not worker.process.is_alive():
						worker.worker_state = WorkerState.STOPPED
						worker.pid = 0
						continue
					any_alive = True
					if diff < self.worker_stop_timeout:
						continue

					logger.warning(
						"Timed out after %d seconds while waiting for worker %d to stop, stopping worker process (SIGKILL)",
						diff,
						worker.pid,
					)
					worker.process.kill()
					break
				if not any_alive:
					break
				time.sleep(0.5)

		if remove_worker:
			for worker in workers:
				self.workers.pop(worker.id, None)

	def restart_worker(self, worker: Worker) -> None:
		with self.worker_update_lock:
			logger.notice("Restarting %s", worker)
			if worker.process and worker.process.is_alive():
				self.stop_worker(worker, wait=True, remove_worker=False)
			self.start_worker(worker)

	def adjust_worker_count(self) -> None:
		with self.worker_update_lock:
			while len(self.workers) < config.workers:
				self.start_worker()
			while len(self.workers) > config.workers:
				self.stop_worker(self.get_workers()[-1])

	def update_worker_state(self) -> None:
		with self.worker_update_lock, redis_client() as redis:
			for redis_key_b in redis.scan_iter(f"{config.redis_key('state')}:workers:*"):
				try:
					worker_info = WorkerInfo.from_dict(redis.hgetall(redis_key_b))
				except Exception as err:
					logger.error("Failed to read worker info from %r, deleting key: %s", redis_key_b.decode("utf-8"), err)
					redis.delete(redis_key_b)
					continue
				if worker_info.node_name == self.node_name:
					if worker_info.id not in self.workers:
						# Delete obsolete worker entry
						redis.delete(redis_key_b)
				else:
					self.workers[worker_info.id] = worker_info


class DepotserverManagerMessagebusListener(MessagebusListener):
	def message_received(self, message: Message) -> None:
		logger.debug("Message received: %s", message)
		if isinstance(message, TraceRequestMessage):
			response = TraceResponseMessage(
				sender=CONNECTION_USER_CHANNEL,
				channel=message.back_channel or message.sender,
				ref_id=message.id,
				req_trace=message.trace,
				payload=message.payload,
				trace={"sender_ws_send": mb_timestamp()},
			)
			assert self.messagebus
			self.messagebus.send_message(response)
		elif isinstance(message, ChannelSubscriptionEventMessage):
			logger.debug("Channels subscription event: %s", message.to_dict())


class Manager(metaclass=Singleton):
	def __init__(self, install_signal_handlers: bool = True) -> None:
		self._install_signal_handlers = install_signal_handlers
		self.pid: int | None = None
		self._async_main_stopped = Event()
		self._loop = asyncio.new_event_loop()
		self._last_reload = 0
		self._should_stop = False
		self._force_stop = False
		self._server_cert_check_time = time.time()
		self._redis_check_time = time.time()
		self._redis_check_interval = 300
		self._messagebus_cleanup_time = 0.0
		self._messagebus_cleanup_interval = 180
		self._cleanup_file_storage_time = 0.0
		self._cleanup_file_storage_interval = 3600
		self._metrics_collector = ManagerMetricsCollector()
		self._worker_manager = WorkerManager()
		self._is_config_server = get_server_role() == "configserver"
		self._service_client: ServiceClient | None = None
		if not self._is_config_server:
			self._service_client = get_service_client("manager")

	@property
	def startup_completed(self) -> Event:
		return self._worker_manager.startup_completed

	def stop(self, force: bool = False) -> None:
		self._should_stop = True
		self._force_stop = force
		logger.notice("Manager stopping force=%s", self._force_stop)
		self._metrics_collector.stop()
		self._worker_manager.stop(self._force_stop)
		if self._service_client:
			self._service_client.disconnect()
		self._async_main_stopped.wait(5.0)

	def reload(self) -> None:
		self._last_reload = int(time.time())
		logger.notice("Manager process %s reloading", self.pid)
		config.reload()
		init_logging(log_mode=config.log_mode)
		log_config()
		self._worker_manager.reload()

	def signal_handler(self, signum: int, frame: FrameType | None) -> None:
		# <CTRL>+<C> will send SIGINT to the entire process group on linux.
		# So child processes will receive the SIGINT too.
		logger.info("Manager process %s received signal %d", self.pid, signum)
		if signum == signal.SIGHUP:
			if time.time() - self._last_reload > 2:
				self.reload()
		else:
			if self._force_stop:
				# Already forced to stop
				return

			# Force on repetition
			self.stop(force=bool(self._should_stop))

	def run(self) -> None:
		logger.info("Manager starting")
		self._should_stop = False
		self.pid = os.getpid()
		self._last_reload = int(time.time())
		if self._install_signal_handlers:
			signal.signal(signal.SIGINT, self.signal_handler)  # Unix signal 2. Sent by Ctrl+C. Terminate service.
			signal.signal(signal.SIGTERM, self.signal_handler)  # Unix signal 15. Sent by `kill <pid>`. Terminate service.
			signal.signal(signal.SIGHUP, self.signal_handler)  # Unix signal 1. Sent by `kill -HUP <pid>`. Reload config.

		if self._service_client:
			listener = DepotserverManagerMessagebusListener(self._service_client.messagebus)
			self._service_client.messagebus.register_messagebus_listener(listener)
			self._service_client.connect_messagebus()
		try:
			Thread(name="ManagerAsyncLoop", daemon=True, target=self.run_loop).start()
			self._worker_manager.run()
		except Exception as exc:
			logger.error(exc, exc_info=True)

	def run_loop(self) -> None:
		pool_executer = ThreadPoolExecutor(max_workers=MANAGER_THREAD_POOL_WORKERS, thread_name_prefix="manager-ThreadPoolExecutor")
		self._loop.set_default_executor(pool_executer)
		self._loop.set_debug("asyncio" in config.debug_options)
		asyncio.set_event_loop(self._loop)
		self._loop.run_until_complete(self.async_main())
		pool_executer.shutdown()

	async def check_server_cert(self) -> None:
		if setup_ssl():
			logger.notice("Server certificate changed, restarting all workers")
			self._worker_manager.restart_workers()
		self._server_cert_check_time = time.time()

	async def check_redis(self) -> None:
		redis_info = await async_get_redis_info(await async_redis_client())
		for key_type in redis_info["key_info"]:
			if redis_info["key_info"][key_type]["memory"] > 100_1000_1000:
				logger.warning(
					"High redis memory usage for '%s': %s",
					key_type,
					redis_info["key_info"][key_type],
				)
		self._redis_check_time = time.time()

	async def async_main(self) -> None:
		# Start MetricsCollector
		asyncio_create_task(self._metrics_collector.main_loop(), self._loop)

		if self._is_config_server:
			# TODO: Multiple managers on different nodes
			await run_in_threadpool(rpc_cache_clear)
			await messagebus_cleanup(full=True)

			app_state: NormalState | MaintenanceState = NormalState()
			if config.maintenance is not False:
				app_state = MaintenanceState(address_exceptions=config.maintenance + ["127.0.0.1/32", "::1/128"])
			asyncio_create_task(app.app_state_manager_task(manager_mode=True, init_app_state=app_state), self._loop)

			if config.zeroconf:
				try:
					await register_opsi_services()
				except Exception as err:
					logger.error("Failed to register opsi service via zeroconf: %s", err, exc_info=True)

		while not self._should_stop:
			try:
				now = time.time()
				if now - self._server_cert_check_time > config.ssl_server_cert_check_interval:
					await self.check_server_cert()
				if now - self._cleanup_file_storage_time > self._cleanup_file_storage_interval:
					await run_in_threadpool(cleanup_file_storage)
					self._cleanup_file_storage_time = now
				if now - self._redis_check_time > self._redis_check_interval:
					await self.check_redis()
				if self._is_config_server:
					if now - self._messagebus_cleanup_time > self._messagebus_cleanup_interval:
						await messagebus_cleanup(full=False)
						self._messagebus_cleanup_time = now

			except Exception as err:
				logger.error(err, exc_info=True)
			for _num in range(60):
				if self._should_stop:
					break
				await asyncio.sleep(1)

		if self._is_config_server:
			await run_in_threadpool(app.set_app_state, ShutdownState())

			if config.zeroconf:
				try:
					await unregister_opsi_services()
				except Exception as err:
					logger.error("Failed to unregister opsi service via zeroconf: %s", err, exc_info=True)

		self._async_main_stopped.set()
