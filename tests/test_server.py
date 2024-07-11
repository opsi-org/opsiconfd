# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
server tests
"""

import time
from threading import Thread

from opsicommon.client.opsiservice import ServiceClient, ServiceVerificationFlags

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	UnprotectedBackend,
	opsiconfd_server,
)


def test_server_thread_limiter() -> None:  # noqa: F811
	executor_workers = 5
	sleep_time = 3
	with opsiconfd_server({"executor_workers": executor_workers}) as server_conf:
		with ServiceClient(
			address=f"https://localhost:{server_conf.port}",
			username=ADMIN_USER,
			password=ADMIN_PASS,
			verify=ServiceVerificationFlags.ACCEPT_ALL,
		) as client:
			for num_clients in executor_workers, executor_workers + 1:
				threads: list[Thread] = []
				for _ in range(num_clients):
					threads.append(Thread(target=client.jsonrpc, args=("sleep", [sleep_time])))

				print("Starting threads")
				start = time.time()
				for thread in threads:
					thread.start()
				for thread in threads:
					thread.join()
				diff = time.time() - start
				print(f"Threads ended after {diff:0.3f} seconds")
				if num_clients <= executor_workers:
					# All clients should be served at the same time
					assert diff < sleep_time * 2
				else:
					# Only executor_workers clients should be served at the same time
					# The rest should be served after the first clients are done
					assert diff >= sleep_time * 2
