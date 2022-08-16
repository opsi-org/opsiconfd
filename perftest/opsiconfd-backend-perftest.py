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
from typing import Any, Union
from urllib.parse import urlparse

import httpx
from opsicommon.utils import generate_opsi_host_key

"""
HOSTS = [
	{
		"id": "agorumcore-tst.uib.local",
		"description": "",
		"notes": "",
		"hardwareAddress": "08:00:27:8a:6c:e5",
		"ipAddress": "192.168.10.188",
		"inventoryNumber": "",
		"opsiHostKey": "a1774639ff86af3c4666af52190bed30",
		"created": "2020-03-06 13:50:08",
		"lastSeen": "2020-03-06 13:50:08",
		"oneTimePassword": null,
		"type": "OpsiClient",
		"ident": "agorumcore-tst.uib.local",
	},
]
"""


async def jsonrpc_request(client: httpx.AsyncClient, url: str, method: str, *params: Any) -> Any:
	params = params or []
	response = await client.post(url, json={"id": 0, "method": method, "params": params})
	response.raise_for_status()
	res = response.json()
	if res["error"]:
		raise RuntimeError(res["error"])
	return res["result"]


class TestManager:  # pylint: disable=too-few-public-methods
	def __init__(self) -> None:
		arg_parser = argparse.ArgumentParser()
		arg_parser.add_argument(
			"-s", "--server", action="store", type=str, help="Configserver url / address", default="https://localhost:4447"
		)
		arg_parser.add_argument("-u", "--username", action="store", type=str, help="Auth username", default="adminuser")
		arg_parser.add_argument("-p", "--password", action="store", type=str, help="Auth password", default="adminuser")
		arg_parser.add_argument("-c", "--clients", action="store", type=int, help="Number of clients", default=10)
		self.args = arg_parser.parse_args()
		url = urlparse(self.args.server)
		self.args.jsonrpc_url = f"{url.scheme or 'https'}://{url.hostname}:{url.port or 4447}{url.path or '/rpc'}"
		self.test_clients = [TestClient(self) for _ in range(self.args.clients)]

	async def main(self) -> None:
		async with httpx.AsyncClient(
			auth=(self.args.username, self.args.username),
			verify=False,
			follow_redirects=True,
			timeout=httpx.Timeout(connect=5, read=60, write=60, pool=5),
		) as client:
			hosts = [{"type": "OpsiClient", "id": f"client{i}.opsi.test", "opsiHostKey": generate_opsi_host_key()} for i in range(1000)]
			await jsonrpc_request(client, self.args.jsonrpc_url, "host_createObjects", hosts)
			await asyncio.gather(*[client.run() for client in self.test_clients])
			await asyncio.gather(*[client.teardown() for client in self.test_clients])
			await jsonrpc_request(client, self.args.jsonrpc_url, "host_deleteObjects", hosts)


class TestClient:  # pylint: disable=too-few-public-methods
	def __init__(self, test_manager: TestManager) -> None:
		self.test_manager = test_manager
		self.client = httpx.AsyncClient(
			auth=(test_manager.args.username, test_manager.args.username),
			verify=False,
			follow_redirects=True,
			timeout=httpx.Timeout(connect=5, read=60, write=60, pool=5),
		)

	async def run(self) -> None:
		await jsonrpc_request(self.client, self.test_manager.args.jsonrpc_url, "authenticated")

	async def teardown(self) -> None:
		await self.client.aclose()


if __name__ == "__main__":
	asyncio.run(TestManager().main())
