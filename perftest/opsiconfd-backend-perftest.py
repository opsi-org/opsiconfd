#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

# pylint: disable=invalid-name
"""
opsiconfd backend performance tests
"""

import argparse
import asyncio
import sys
import time
from asyncio import sleep
from datetime import datetime, timezone
from itertools import product
from statistics import mean, median
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx


class TestManager:  # pylint: disable=too-few-public-methods
	def __init__(self) -> None:
		arg_parser = argparse.ArgumentParser()
		arg_parser.add_argument("--server", action="store", type=str, help="Configserver url / address", default="https://localhost:4447")
		arg_parser.add_argument("--username", action="store", type=str, help="Auth username", default="adminuser")
		arg_parser.add_argument("--password", action="store", type=str, help="Auth password", default="adminuser")
		arg_parser.add_argument("--clients", action="store", type=int, help="Number of clients", default=1000)
		arg_parser.add_argument("--products", action="store", type=int, help="Number of products", default=100)
		arg_parser.add_argument("--iterations", action="store", type=int, help="Number of test repetitions", default=3)
		arg_parser.add_argument(
			"--max-real", action="store", type=int, help="Fail if real time spent exceeds this value (in ms)", default=0
		)
		self.args = arg_parser.parse_args()
		url = urlparse(self.args.server)
		base_url = f"{url.scheme or 'https'}://{url.hostname}:{url.port or 4447}"
		self.args.jsonrpc_url = f"{base_url}/rpc"
		self.args.metrics_url = f"{base_url}/metrics/grafana"
		self.request_stats: List[float] = []

	async def jsonrpc_request(self, client: httpx.AsyncClient, url: str, method: str, *params: Any) -> Any:
		params = params or tuple()
		start = time.time()
		response = await client.post(url, json={"id": 0, "method": method, "params": params})
		self.request_stats.append(time.time() - start)
		response.raise_for_status()
		res = response.json()
		if res["error"]:
			raise RuntimeError(res["error"])
		return res["result"]

	async def get_cpu_usage(self, client: httpx.AsyncClient, start: datetime, end: datetime) -> int:
		response = await client.post(f"{self.args.metrics_url}/search")
		response.raise_for_status()

		timeseries_worker_cpu = None
		for timeserie in response.json():
			if "CPU usage of worker 1" in timeserie:
				timeseries_worker_cpu = timeserie
				break
		if not timeseries_worker_cpu:
			raise RuntimeError("Failed to find timeseries")

		data = {
			"app": "opsiconfd-backend-perftest",
			"panelId": 1,
			"timezone": "browser",
			"range": {
				"from": start.isoformat(),
				"to": end.isoformat(),
				"raw": {},
			},
			"intervalMs": 500,
			"targets": [{"target": timeseries_worker_cpu, "refId": "A", "type": "timeserie"}],
			"format": "json",
		}
		response = await client.post(f"{self.args.metrics_url}/query", json=data)
		response.raise_for_status()

		if not response.json()[0]["datapoints"]:
			return 0
		return round(response.json()[0]["datapoints"][-1][0])

	async def run_test(self) -> Dict[str, int]:
		self.request_stats = []
		test_clients = [TestClient(self, f"client{c}.opsi.test") for c in range(min(self.args.clients, 100))]
		async with httpx.AsyncClient(
			auth=(self.args.username, self.args.username),
			verify=False,
			follow_redirects=True,
			timeout=httpx.Timeout(connect=5, read=120, write=120, pool=5),
		) as client:
			start = datetime.now(tz=timezone.utc)
			hosts = [
				{"type": "OpsiClient", "id": f"client{h}.opsi.test", "opsiHostKey": "ffffffffffffffffffffffffffffffff"}
				for h in range(self.args.clients)
			]
			await self.jsonrpc_request(client, self.args.jsonrpc_url, "host_createObjects", hosts)

			products = [
				{"type": "LocalbootProduct", "id": f"product{p}", "productVersion": "1.0", "packageVersion": "1"}
				for p in range(self.args.products)
			]
			await self.jsonrpc_request(client, self.args.jsonrpc_url, "product_createObjects", products)

			product_on_clients = [
				{"type": "ProductOnClient", "productType": p["type"], "productId": p["id"], "clientId": h["id"]}
				for h, p in list(product(hosts, products))[0::10]
			]
			await self.jsonrpc_request(client, self.args.jsonrpc_url, "productOnClient_createObjects", product_on_clients)

			await asyncio.gather(*[client.run() for client in test_clients])
			await asyncio.gather(*[client.teardown() for client in test_clients])

			await self.jsonrpc_request(client, self.args.jsonrpc_url, "productOnClient_deleteObjects", product_on_clients)
			await self.jsonrpc_request(client, self.args.jsonrpc_url, "product_deleteObjects", products)
			await self.jsonrpc_request(client, self.args.jsonrpc_url, "host_deleteObjects", hosts)

			end = datetime.now(tz=timezone.utc)
			worker_cpu_usage = await self.get_cpu_usage(client, start, end)

		return {
			"count": len(self.request_stats),
			"sum": round(sum(self.request_stats) * 1000),
			"mean": round(mean(self.request_stats) * 1000),
			"median": round(median(self.request_stats) * 1000),
			"real": round((end - start).total_seconds() * 1000),
			"cpu": worker_cpu_usage,
		}

	async def main(self) -> None:
		stats = []
		for num in range(1, self.args.iterations + 1):
			stats.append(await self.run_test())
			if num < self.args.iterations:
				await sleep(5)

		avg_stats = {key: round(mean([s[key] for s in stats])) for key in list(stats[0])}

		print("rpc statistics (ms):")
		for k, v in avg_stats.items():
			print(f"{k}={v}")

		if self.args.max_real > 0 and avg_stats["real"] > self.args.max_real:
			print(f"real time of {avg_stats['real']} ms exceeds limit of {self.args.max_real} ms")
			sys.exit(1)


class TestClient:  # pylint: disable=too-few-public-methods
	def __init__(self, test_manager: TestManager, client_id: str) -> None:
		self.test_manager = test_manager
		self.client_id = client_id
		self.client = httpx.AsyncClient(
			auth=(self.client_id, "ffffffffffffffffffffffffffffffff"),
			verify=False,
			follow_redirects=True,
			timeout=httpx.Timeout(connect=5, read=60, write=60, pool=5),
		)

	async def run(self) -> None:
		await self.test_manager.jsonrpc_request(self.client, self.test_manager.args.jsonrpc_url, "accessControl_authenticated")
		res = await self.test_manager.jsonrpc_request(self.client, self.test_manager.args.jsonrpc_url, "product_getObjects")
		assert res
		res = await self.test_manager.jsonrpc_request(
			self.client, self.test_manager.args.jsonrpc_url, "productOnClient_getObjects", [], {"clientId": self.client_id}
		)
		assert res
		await self.test_manager.jsonrpc_request(self.client, self.test_manager.args.jsonrpc_url, "backend_exit")

	async def teardown(self) -> None:
		await self.client.aclose()


if __name__ == "__main__":
	asyncio.run(TestManager().main())
