# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
server tests
"""
import threading
import time

import psutil

from opsiconfd.server import Server

from .utils import BackendManager, backend, get_config  # pylint: disable=unused-import


def test_server_and_workers() -> None:
	with get_config({"port": 4444, "workers": 1, "log_mode": "local"}):
		server = Server()
		server_thread = threading.Thread(target=server.run)
		server_thread.start()

		time.sleep(3)

		assert len(server.workers) == 1
		assert server.workers[0].worker_num == 1
		proc = psutil.Process(server.workers[0].pid)
		assert proc.is_running()

		worker_pid = server.workers[0].pid
		server.restart_workers()

		time.sleep(10)

		assert len(server.workers) == 1
		assert server.workers[0].worker_num == 1
		proc = psutil.Process(server.workers[0].pid)
		assert proc.is_running()

		assert worker_pid != server.workers[0].pid

		time.sleep(3)

		server.stop()
		server_thread.join()


def test_check_modules(backend: BackendManager) -> None:  # pylint: disable=redefined-outer-name
	scalability_available = "scalability1" in backend.backend_getLicensingInfo()["available_modules"]
	with get_config({"port": 4444, "workers": 2, "log_mode": "local"}) as config:
		server = Server()
		server.check_modules()
		if scalability_available:
			assert config.workers == 2
		else:
			assert config.workers == 1
