#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

# pylint: disable=invalid-name
"""
opsiconfd backend performance tests
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import random
import statistics
import sys
import time
import traceback
from asyncio import get_event_loop
from typing import AsyncGenerator
from urllib.parse import urlparse

import httpx


class FileDownloadClient:  # pylint: disable=too-many-instance-attributes
	def __init__(self, test_manager: TestManager, name: str) -> None:
		self.test_manager = test_manager
		self.name = name
		self.loop: asyncio.AbstractEventLoop | None = None
		self.should_exit = asyncio.Event()
		self.exception: Exception | None = None
		self.chunk_size = 1_000_000
		self.range_request = True
		chunks = self.test_manager.args.file_size / self.chunk_size
		self.wait_time = self.test_manager.args.min_download_time / chunks
		self.range_header = ""
		self._ranges = [[0, self.test_manager.args.file_size - 1]]
		if self.test_manager.args.range_requests:
			self._ranges = [
				[0, int(chunks / 2) * self.chunk_size - 1],
				[int(chunks / 2) * self.chunk_size, self.test_manager.args.file_size - 1],
			]
		self.bytes_received = 0

	async def run(self) -> None:
		self.loop = get_event_loop()
		try:
			async with httpx.AsyncClient(verify=False, auth=(self.test_manager.args.username, self.test_manager.args.password)) as client:
				for range in self._ranges:
					headers = {}
					if range[0] != 0 or range[1] != self.test_manager.args.file_size - 1:
						headers = {"Range": f"bytes={range[0]}-{range[1]}"}
					async with client.stream("GET", self.test_manager.args.file_url, headers=headers) as response:
						start = time.time()
						async for data in response.aiter_bytes(chunk_size=self.chunk_size):
							self.bytes_received += len(data)
							print(".", end="", flush=True)
							sleep_time = max(0, self.wait_time - (time.time() - start))
							if sleep_time:
								await asyncio.sleep(sleep_time)
							start = time.time()
			if self.bytes_received != self.test_manager.args.file_size:
				raise RuntimeError(f"Received {self.bytes_received} bytes, expected {self.test_manager.args.file_size} bytes")
		except Exception as err:  # pylint: disable=broad-except
			print(f"Exception in {self.name}: {err}")
			traceback.print_exc()
			self.exception = err
		finally:
			self.should_exit.set()


class TestManager:  # pylint: disable=too-few-public-methods
	def __init__(self) -> None:
		arg_parser = argparse.ArgumentParser()
		arg_parser.add_argument("--server", action="store", type=str, help="Configserver url / address", default="https://localhost:4447")
		arg_parser.add_argument("--username", action="store", type=str, help="Auth username", default="adminuser")
		arg_parser.add_argument("--password", action="store", type=str, help="Auth password", default="adminuser")
		arg_parser.add_argument("--clients", action="store", type=int, help="Number of clients", default=1)
		arg_parser.add_argument("--file-size", action="store", type=int, help="Download file size in MB", default=500)
		arg_parser.add_argument("--range-requests", action="store_true", help="Use range requests")
		arg_parser.add_argument(
			"--memory-usage-limit", action="store", type=int, help="Fail if memory usage exceeds this value (in MB)", default=10
		)
		arg_parser.add_argument(
			"--min-download-time", action="store", type=int, help="Minimum time the download should take (in seconds)", default=20
		)
		self.args = arg_parser.parse_args()
		url = urlparse(self.args.server)
		self.args.base_url = f"{url.scheme or 'https'}://{url.hostname}:{url.port or 4447}"
		self.args.file_size = int(self.args.file_size * 1_000_000)
		self.args.memory_usage_limit = int(self.args.memory_usage_limit * 1_000_000)

	async def get_worker_memory_usage(self, start_time: int, end_time: int) -> tuple[int, int]:
		target_names = []
		async with httpx.AsyncClient(verify=False, auth=(self.args.username, self.args.password)) as client:
			res = await client.get(self.args.base_url + "/metrics/grafana/search")
			res.raise_for_status()
			target_names = [name for name in res.json() if name.startswith("Average memory usage of worker")]

			assert target_names
			_from = datetime.datetime.fromtimestamp(start_time)
			_to = datetime.datetime.fromtimestamp(end_time)
			targets = [{"type": "timeserie", "target": name, "refId": "A"} for name in target_names]
			query = {
				"app": "dashboard",
				"range": {"from": f"{_from.isoformat()}Z", "to": f"{_to.isoformat()}Z", "raw": {}},
				"intervalMs": 500,
				"timezone": "utc",
				"targets": targets,
			}

			res = await client.post(self.args.base_url + "/metrics/grafana/query", json=query)
			res.raise_for_status()
			max_workers_memory_usage = 0
			avg_workers_memory_usage = 0
			for data in res.json():
				max_workers_memory_usage += max([dat[0] for dat in data["datapoints"]])
				avg_workers_memory_usage += statistics.mean([dat[0] for dat in data["datapoints"]])
			return int(avg_workers_memory_usage), int(max_workers_memory_usage)

	async def main(self) -> None:
		start = int(time.time())
		# Wait until some memory metrics are generated
		await asyncio.sleep(10)
		now = int(time.time())

		start_memory = (await self.get_worker_memory_usage(start_time=start, end_time=now))[0]
		print(f"start_memory: {(start_memory / 1_000_000):0.3f} MB")

		async def test_data() -> AsyncGenerator[bytes, None]:
			bytes_sent = 0
			while bytes_sent < self.args.file_size:
				chunk_size = min(self.args.file_size - bytes_sent, 1_000_000)
				yield random.randbytes(chunk_size)
				bytes_sent += chunk_size

		test_file = "/repository/file-download-test-file"
		self.args.file_url = f"{self.args.base_url}{test_file}"
		async with httpx.AsyncClient(verify=False, auth=(self.args.username, self.args.password)) as client:
			res = await client.put(self.args.file_url, content=test_data(), timeout=20)
			res.raise_for_status()

		try:
			test_clients = [FileDownloadClient(self, name=f"download client{c+1}") for c in range(self.args.clients)]
			start = int(time.time())
			await asyncio.gather(*[client.run() for client in test_clients])
			now = int(time.time())
			print("")
			max_memory_usage = (await self.get_worker_memory_usage(start_time=start, end_time=now))[1] - start_memory
			exceptions = [client.exception for client in test_clients if client.exception]
			if exceptions:
				print(f"{len(exceptions)} exceptions occurred")
				sys.exit(1)
			print(f"max_memory_usage: {(max_memory_usage / 1_000_000):0.3f} MB")
			if max_memory_usage > self.args.memory_usage_limit:
				print(
					f"Memory usage of {(max_memory_usage / 1_000_000):0.3f} MB "
					f"exceeds limit of {(self.args.memory_usage_limit / 1_000_000):0.3f} MB"
				)
				sys.exit(1)
		finally:
			async with httpx.AsyncClient(verify=False, auth=(self.args.username, self.args.password)) as client:
				res = await client.delete(self.args.file_url)
				res.raise_for_status()


if __name__ == "__main__":
	asyncio.run(TestManager().main())
