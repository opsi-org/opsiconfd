# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
Test opsiconfd.manager
"""

import asyncio
import os
import signal
import threading
import time
from typing import Generator
from unittest.mock import patch

import psutil
import pytest

from opsiconfd.manager import Manager, WorkerManager, WorkerState

from .utils import (  # pylint: disable=unused-import
	UnprotectedBackend,
	backend,
	get_config,
	reset_singleton,
)


@pytest.fixture()
def manager() -> Generator[Manager, None, None]:  # pylint: disable=redefined-outer-name
	with (
		patch("opsiconfd.manager.WorkerManager.run", lambda *args, **kwargs: None),
		patch("opsiconfd.manager.init_logging", lambda *args, **kwargs: None),
		patch("opsiconfd.manager.register_opsi_services", lambda *args, **kwargs: asyncio.sleep(0.1)),
		patch("opsiconfd.manager.unregister_opsi_services", lambda *args, **kwargs: asyncio.sleep(0.1)),
	):
		reset_singleton(Manager)
		man = Manager()
		man.run()
		try:
			yield man
		finally:
			man.stop()


def test_manager_signals(manager: Manager) -> None:  # pylint: disable=redefined-outer-name
	# signal_handler is replaced in conftest

	test_reload = False

	def reload() -> None:
		nonlocal test_reload
		test_reload = True

	setattr(manager, "reload", reload)

	manager._last_reload = 0  # pylint: disable=protected-access
	manager.orig_signal_handler(signal.SIGHUP, None)  # type: ignore[attr-defined]
	assert test_reload is True

	test_reload = False
	manager._last_reload = int(time.time())  # pylint: disable=protected-access
	manager.orig_signal_handler(signal.SIGHUP, None)  # type: ignore[attr-defined]
	assert test_reload is False

	test_stop = ""

	def stop(force: bool = False) -> None:
		nonlocal test_stop
		test_stop = "force" if force else "normal"

	setattr(manager._worker_manager, "stop", stop)  # pylint: disable=protected-access
	manager.orig_signal_handler(signal.SIGKILL, None)  # type: ignore[attr-defined]
	assert manager._should_stop is True  # pylint: disable=protected-access
	assert test_stop == "normal"
	time.sleep(0.1)
	manager.orig_signal_handler(signal.SIGKILL, None)  # type: ignore[attr-defined]
	assert manager._should_stop is True  # pylint: disable=protected-access
	assert test_stop == "force"


@pytest.mark.parametrize("cert_changed", (False, True))
def test_check_server_cert(manager: Manager, cert_changed: bool) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	test_restarted = False

	def restart_workers(self: WorkerManager) -> None:  # pylint: disable=unused-argument
		nonlocal test_restarted
		test_restarted = True

	with (
		patch("opsiconfd.manager.WorkerManager.restart_workers", restart_workers),
		patch("opsiconfd.manager.setup_server_cert", lambda: cert_changed),
	):
		with get_config({"ssl_server_cert_check_interval": 0.00001}):
			time.sleep(2)
			assert test_restarted == cert_changed


def test_worker_manager_and_workers() -> None:
	def wait_for_workers_running(worker_manager: WorkerManager, count: int, timeout: int = 10) -> None:
		for _ in range(timeout):
			if len(worker_manager.workers) == count:
				num_running = 0
				for worker in worker_manager.workers.values():
					if worker.worker_state == WorkerState.RUNNING:
						try:
							proc = psutil.Process(worker.pid)
						except psutil.NoSuchProcess:
							continue
						if proc.is_running():
							num_running += 1
				if num_running == count:
					return
			time.sleep(1)
		raise RuntimeError("Timed out while waiting for workers")

	with get_config({"port": 4444, "workers": 2, "log_mode": "local"}):
		worker_manager = WorkerManager()
		worker_manager.worker_restart_gap = 0.0
		worker_manager.worker_check_interval = 2.0
		worker_manager.startup_time = 10.0
		worker_manager_thread = threading.Thread(target=worker_manager.run, daemon=True)
		worker_manager_thread.start()
		try:
			wait_for_workers_running(worker_manager, count=2)

			# Assert startup phase not yet set to completed
			assert worker_manager.startup
			time.sleep(worker_manager.startup_time)
			# Assert startup phase set to completed
			assert not worker_manager.startup

			assert len(worker_manager.workers) == 2
			assert worker_manager.workers[f"{worker_manager.node_name}:1"].worker_num == 1
			assert worker_manager.workers[f"{worker_manager.node_name}:2"].worker_num == 2
			pid1 = worker_manager.workers[f"{worker_manager.node_name}:1"].pid
			pid2 = worker_manager.workers[f"{worker_manager.node_name}:2"].pid
			proc1 = psutil.Process(pid1)
			proc2 = psutil.Process(pid2)
			assert proc1.is_running()
			assert proc2.is_running()

			# Kill worker process
			os.kill(pid1, signal.SIGKILL)
			for _ in range(10):
				if not proc1.is_running():
					break
				time.sleep(1)

			assert not proc1.is_running()
			assert proc2.is_running()

			# Assert that worker process is restarted with new pid
			wait_for_workers_running(worker_manager, count=2)
			assert worker_manager.workers[f"{worker_manager.node_name}:1"].pid != pid1
			assert worker_manager.workers[f"{worker_manager.node_name}:2"].pid == pid2
			pid1 = worker_manager.workers[f"{worker_manager.node_name}:1"].pid
			pid2 = worker_manager.workers[f"{worker_manager.node_name}:2"].pid
			proc1 = psutil.Process(pid1)
			proc2 = psutil.Process(pid2)
			assert proc1.is_running()
			assert proc2.is_running()

			# Restart workers
			worker_manager.restart_workers(wait=True)
			for _ in range(10):
				if not proc1.is_running() and not proc2.is_running():
					break
				time.sleep(1)
			assert not proc1.is_running()
			assert not proc2.is_running()

			# Assert that worker processes are restarted with new pid
			wait_for_workers_running(worker_manager, count=2)
			assert worker_manager.workers[f"{worker_manager.node_name}:1"].pid != pid1
			assert worker_manager.workers[f"{worker_manager.node_name}:2"].pid != pid2

		finally:
			worker_manager.stop()
			worker_manager_thread.join()


def test_check_modules(backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	scalability_available = "scalability1" in backend.backend_getLicensingInfo()["available_modules"]
	with get_config({"port": 4444, "workers": 2, "log_mode": "local"}) as config:
		worker_manager = WorkerManager()
		worker_manager.check_modules()
		if scalability_available:
			assert config.workers == 2
		else:
			assert config.workers == 1
