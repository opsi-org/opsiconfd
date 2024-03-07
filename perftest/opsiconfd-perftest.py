#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

# pylint: disable=invalid-name
"""
opsiconfd performance test util
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import getpass
import gzip
import json as pyjson
import os
import shutil
import signal
import sys
import tempfile
import time
import uuid
import zlib
from asyncio import sleep
from concurrent.futures import ProcessPoolExecutor
from typing import Any, AsyncGenerator, Optional, Type, Union
from urllib.parse import urlparse

import aiohttp
import lz4.frame  # type: ignore[import]
import uvloop
from msgspec import json, msgpack
from opsicommon.messagebus import (  # type: ignore[import]
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
)

executor = ProcessPoolExecutor(max_workers=25)


class Perftest:  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self,
		server: str,
		username: str,
		password: str,
		clients: int,
		iterations: int = 1,
		compression: str | None = None,
		print_responses: bool = False,
		jsonrpc_methods: Optional[list[str]] = None,
		write_results: str | None = None,
		bencher_results: str | None = None,
		bencher_measure: str | None = None,
		max_avg_seconds_per_request: float = 0,
		max_errors: int = -1,
	) -> None:
		url = urlparse(server)
		self.base_url = f"{url.scheme or 'https'}://{url.hostname or url.path}:{url.port or 4447}"
		self.username = username
		self.password = password
		self.num_clients = clients if clients and clients > 0 else 1
		self.iterations = iterations
		self.compression = compression
		self.print_responses = print_responses
		self.test_cases = []
		self.write_results = write_results
		self.bencher_results = bencher_results
		self.bencher_measure = bencher_measure
		self.max_avg_seconds_per_request = max_avg_seconds_per_request
		self.max_errors = max_errors
		if self.write_results:
			with open(self.write_results, "wb"):
				pass

		if jsonrpc_methods:
			requests = []
			for meth in jsonrpc_methods:
				tmp = meth.split("[", 1)
				method = tmp[0]
				params = []
				if len(tmp) > 1:
					params = json.decode(("[" + tmp[1]).encode("utf-8"))  # pylint: disable=dotted-import-in-loop
				requests.append(["jsonrpc", method, params])
			self.test_cases = [TestCase(self, "JSONRPC", {"test": requests})]

	async def signal_handler(self, _sig: int) -> None:
		await self.stop()

	@classmethod
	def from_file(cls: Type, filename: str, **kwargs: Any) -> Perftest:
		with open(filename, "rb") as file:
			perftest = json.decode(file.read())
			for key, var in kwargs.items():
				if var is None or key == "load":
					continue
				perftest[key] = var
			test_cases = []
			if perftest.get("test_cases"):
				test_cases = copy.deepcopy(perftest["test_cases"])
				del perftest["test_cases"]
			perft = Perftest(**perftest)
			for test_case in test_cases:
				test_case["perftest"] = perft
				testc = TestCase(**test_case)
				perft.test_cases.append(testc)
			return perft

	async def run(self) -> None:
		loop = asyncio.get_event_loop()
		signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
		for sig in signals:
			loop.add_signal_handler(sig, lambda sig=sig: loop.create_task(self.signal_handler(sig)))

		for test_case in self.test_cases:
			await test_case.run()
			results = test_case.calc_results()
			if self.max_errors >= 0 and results["errors"] > self.max_errors:
				print(f"Number of errors exceeded {self.max_errors}")
				sys.exit(1)
			if self.max_avg_seconds_per_request > 0 and results["avg_seconds_per_request"] > self.max_avg_seconds_per_request:
				print(f"Average time per request exceeded {self.max_avg_seconds_per_request} seconds")
				sys.exit(1)

	async def stop(self) -> None:
		for test_case in self.test_cases:
			await test_case.stop()


class TestCase:  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments
		self, perftest: Perftest, name: str, requests: dict[str, list], compression: str | None = None, encoding: str = "json"
	):
		self.perftest = perftest
		self.name = name
		self.requests = requests
		self.compression = perftest.compression
		if not self.compression:
			self.compression = compression
		if self.compression == "none":
			self.compression = None
		self.encoding = encoding
		self.clients: list[Client] = []
		self.results: list[dict] = []
		self.start: float = 0.0
		self.end: float = 0.0
		self._should_stop = False
		self.server_id: str = "none"

	@property
	def depot_id(self) -> str:
		return self.server_id

	@property
	def num_clients(self) -> int:
		return self.perftest.num_clients

	@property
	def iterations(self) -> int:
		return self.perftest.iterations

	async def stop(self) -> None:
		self._should_stop = True
		if self.start:
			while not self.end:
				await sleep(0.1)

	async def run(self) -> None:
		client = Client(self)
		server_ids = (
			await client.execute_jsonrpc_request(  # type: ignore[index]
				client.jsonrpc_request("host_getIdents", ["str", {"type": "OpsiConfigserver"}])
			)
		)[0]["result"]
		self.server_id = server_ids[0]  # type: ignore[assignment]
		await client.cleanup()

		width = shutil.get_terminal_size((80, 20))[0]  # fallback: 100, 40
		width = min(width, 100)
		print("")
		print(f"===[ Running test '{self.name}' on '{self.perftest.base_url}' ]".ljust(width, "="))
		print(f" * {self.num_clients} concurrent clients")
		print(f" * {self.iterations} iterations")

		self.clients = [Client(self) for _ in range(self.num_clients)]
		try:
			if self.requests.get("setup"):
				tasks = [client.execute_requests(self.requests["setup"], add_results=False) for client in self.clients]
				await asyncio.gather(*tasks)

			await sleep(1)

			self.start = time.perf_counter()
			if self.requests.get("test"):
				for _i in range(self.iterations):
					tasks = [client.execute_requests(self.requests["test"]) for client in self.clients]  # pylint: disable=loop-invariant-statement
					await asyncio.gather(*tasks, return_exceptions=False)  # pylint: disable=dotted-import-in-loop
					if self._should_stop:
						break
			self.end = time.perf_counter()

			if self.requests.get("teardown"):
				tasks = [client.execute_requests(self.requests["teardown"], add_results=False) for client in self.clients]
				await asyncio.gather(*tasks)
		finally:
			tasks = [client.cleanup() for client in self.clients]
			await asyncio.gather(*tasks)

		print("")
		self.display_results()
		if self.perftest.write_results:
			self.write_results()
		if self.perftest.bencher_results and self.perftest.bencher_measure:
			self.write_bencher_results()
		print("")

	def add_result(  # pylint: disable=too-many-arguments
		self, error: None, seconds: float, bytes_sent: int, bytes_received: int, round_trip_time: float
	) -> None:
		res = {
			"error": error,
			"seconds": seconds,
			"bytes_sent": bytes_sent,
			"bytes_received": bytes_received,
			"round_trip_time": round_trip_time,
		}
		self.results.append(res)
		if len(self.results) % 10 == 0:
			sys.stdout.write(".")
			sys.stdout.flush()
		if len(self.results) % 500 == 0:
			sys.stdout.write("\n")
			sys.stdout.flush()

	def calc_results(self) -> dict[str, Any]:
		result = {
			"total_seconds": self.end - self.start,
			"requests": 0,
			"errors": 0,
			"total_request_seconds": 0.0,
			"bytes_sent": 0,
			"bytes_received": 0,
			"avg_requests_per_second": 0,
			"min_seconds_per_request": 0.0,
			"avg_seconds_per_request": 0.0,
			"max_seconds_per_request": 0.0,
			"min_round_trip_time": 0.0,
			"avg_round_trip_time": 0.0,
			"max_round_trip_time": 0.0,
		}

		sum_round_trip_time = 0.0
		for res in self.results:
			result["requests"] += 1  # pylint: disable=loop-invariant-statement
			if res["error"]:
				result["errors"] += 1  # pylint: disable=loop-invariant-statement
			result["total_request_seconds"] += res["seconds"]  # pylint: disable=loop-invariant-statement
			result["bytes_sent"] += res["bytes_sent"]  # pylint: disable=loop-invariant-statement
			result["bytes_received"] += res["bytes_received"]  # pylint: disable=loop-invariant-statement
			if result["min_seconds_per_request"] == 0 or result["min_seconds_per_request"] > res["seconds"]:  # pylint: disable=loop-invariant-statement
				result["min_seconds_per_request"] = res["seconds"]  # pylint: disable=loop-invariant-statement
			if result["max_seconds_per_request"] == 0 or result["max_seconds_per_request"] < res["seconds"]:  # pylint: disable=loop-invariant-statement
				result["max_seconds_per_request"] = res["seconds"]  # pylint: disable=loop-invariant-statement
			sum_round_trip_time += res["round_trip_time"]
			if result["min_round_trip_time"] == 0 or result["min_round_trip_time"] > res["round_trip_time"]:  # pylint: disable=loop-invariant-statement
				result["min_round_trip_time"] = res["round_trip_time"]  # pylint: disable=loop-invariant-statement
			if result["max_round_trip_time"] == 0 or result["max_round_trip_time"] < res["round_trip_time"]:  # pylint: disable=loop-invariant-statement
				result["max_round_trip_time"] = res["round_trip_time"]  # pylint: disable=loop-invariant-statement

		result["avg_seconds_per_request"] = result["total_request_seconds"] / result["requests"]
		result["avg_requests_per_second"] = result["requests"] / result["total_seconds"]
		result["avg_bytes_received_per_second"] = result["bytes_received"] / result["total_seconds"]
		result["avg_bytes_send_per_second"] = result["bytes_sent"] / result["total_seconds"]
		result["avg_round_trip_time"] = sum_round_trip_time / len(self.results)
		return result

	def write_results(self) -> None:
		if not self.perftest.write_results:
			return
		with open(self.perftest.write_results, "a", encoding="utf-8") as file:
			file.write(f"[{self.name}]\n")
			for key, val in self.calc_results().items():
				file.write(f"{key}={val}\n")
			file.write("\n")

	def write_bencher_results(self) -> None:
		if not self.perftest.bencher_results or not self.perftest.bencher_measure:
			return
		bencher_results = {}
		benchmark_name = "opsiconfd-perftest"
		if os.path.exists(self.perftest.bencher_results):
			with open(self.perftest.bencher_results, "r", encoding="utf-8") as file:
				bencher_results = pyjson.loads(file.read())

		results = self.calc_results()
		if benchmark_name not in bencher_results:
			bencher_results[benchmark_name] = {}
		bencher_results[benchmark_name].update(
			{
				self.perftest.bencher_measure: {
					"value": results["avg_seconds_per_request"] * 1000,
					"lower_value": results["min_seconds_per_request"] * 1000,
					"upper_value": results["max_seconds_per_request"] * 1000,
				}
			}
		)

		with open(self.perftest.bencher_results, "w", encoding="utf-8") as file:
			file.write(pyjson.dumps(bencher_results, indent=2))

	def display_results(self) -> None:
		res = self.calc_results()
		print("Results:")
		print(f" * RPC compression: {self.compression or 'none'}")
		print(f" * RPC encoding: {self.encoding}")
		print(f" * Requests: {res['requests']}")
		print(f" * Errors: {res['errors']}")
		print(f" * Total seconds: {res['total_seconds']:0.3f}")
		print(f" * Requests/second: {res['avg_requests_per_second']:0.3f}")
		print(
			" * Request duration: min/avg/max "
			f"{res['min_seconds_per_request']:0.3f}s/{res['avg_seconds_per_request']:0.3f}s/{res['max_seconds_per_request']:0.3f}s"
		)
		print(
			" * Round trip time: min/avg/max "
			f"{res['min_round_trip_time']*1000:0.3f}ms/{res['avg_round_trip_time']*1000:0.3f}ms/{res['max_round_trip_time']*1000:0.3f}ms"
		)
		print(f" * Bytes sent: {res['bytes_sent']/1000/1000:0.2f}MB ({res['avg_bytes_send_per_second']/1000/1000:0.2f}MB/s)")
		print(f" * Bytes received: {res['bytes_received']/1000/1000:0.2f}MB ({res['avg_bytes_received_per_second']/1000/1000:0.2f}MB/s)")
		print("")


class Client:
	def __init__(self, test_case: TestCase) -> None:
		self.test_case = test_case
		self._session: Optional[aiohttp.ClientSession] = None
		self._messagebus_ws: Optional[aiohttp.ClientWebSocketResponse] = None
		self.http_client_id = str(uuid.uuid4())

	@property
	def perftest(self) -> Perftest:
		return self.test_case.perftest

	async def messagebus_ws(self) -> aiohttp.ClientWebSocketResponse:
		if not self._messagebus_ws:
			self._messagebus_ws = await self.session._ws_connect(  # pylint: disable=protected-access
				url=f"{self.perftest.base_url}/messagebus/v1",
				params={"compression": self.test_case.compression if self.test_case.compression else ""},
			)
			await self._messagebus_ws.receive_bytes()
		return self._messagebus_ws

	def _fill_placeholders(self, obj: Any) -> Any:
		if isinstance(obj, bytes):
			return obj
		if isinstance(obj, str):
			return (
				obj.replace("{{http_client_id}}", self.http_client_id)
				.replace("{{server_id}}", self.test_case.server_id)
				.replace("{{depot_id}}", self.test_case.depot_id)
			)
		if isinstance(obj, list):
			return [self._fill_placeholders(o) for o in obj]
		return obj

	@property
	def session(self) -> aiohttp.ClientSession:
		if not self._session:
			self._session = aiohttp.ClientSession(
				connector=aiohttp.TCPConnector(ssl=False),
				auth=aiohttp.BasicAuth(login=self.perftest.username, password=self.perftest.password),
				cookie_jar=aiohttp.CookieJar(unsafe=True),
			)
		return self._session

	async def cleanup(self) -> None:
		if self._session:
			await self._session.close()
		if self._messagebus_ws:
			await self._messagebus_ws.close()

	@staticmethod
	async def random_data_generator(size: int = 0, chunk_size: int = 1000 * 1000) -> AsyncGenerator[bytes, None]:
		with tempfile.TemporaryFile(mode="wb+") as tempf:
			# TODO: more randomized data
			tempf.write(b"o" * size)
			tempf.seek(0)
			sent = 0
			while sent < size:
				data = tempf.read(chunk_size)
				if not data:
					break
				yield data
				sent += len(data)

	async def execute_requests(self, requests: list[list[Any]], add_results: bool = True) -> None:
		for request in requests:
			method = getattr(self, request[0])
			params = self._fill_placeholders(request[1:])
			result = await method(*params)
			if add_results:
				self.test_case.add_result(*result)

	async def websocket(  # pylint: disable=too-many-branches,too-many-locals
		self, path: str, params: dict[str, str] | None = None, data: Any = None, send_data_count: int = 1
	) -> tuple[Optional[str], float, int, int, float]:
		url = f"{self.perftest.base_url}/{path.lstrip('/')}"
		bytes_sent = 0
		if data:
			if isinstance(data, str):
				bytes_sent = len(data.encode("utf-8"))
			bytes_sent = len(data)
		bytes_sent *= send_data_count

		start = time.perf_counter()
		data_received = None
		bytes_received = 0
		error = None
		try:
			async with self.session.ws_connect(url=url, params=params) as websocket:
				for _ in range(send_data_count):
					if data:
						if isinstance(data, str):  # pylint: disable=loop-invariant-statement
							await websocket.send_str(data)
						if isinstance(data, bytes):  # pylint: disable=loop-invariant-statement
							await websocket.send_bytes(data)
						else:
							await websocket.send_json(data)

					msg = await websocket.receive()
					if data_received is None:
						data_received = msg.data
					else:
						data_received += msg.data

		except aiohttp.WSServerHandshakeError as err:
			error = str(err)
		bytes_received = len(data_received) if data_received else 0
		end = time.perf_counter()
		if self.perftest.print_responses or error:
			if error:
				print(f"Error: {error}")
			else:
				print(f"Data received: {data_received}")

		return (error, end - start, bytes_sent, bytes_received, (end - start) / send_data_count)

	async def webdav(
		self, method: str, filename: str, data: Union[AsyncGenerator, bytes, str, None] = None
	) -> tuple[Optional[str], float, int, int, float]:
		url = f"{self.perftest.base_url}/repository/{filename}"
		bytes_sent = 0
		if data:
			if isinstance(data, str):
				data = data.encode("utf-8")
				if data.startswith(b"{{random_data:"):
					bytes_sent = int(data.split(b":")[1].strip(b"}"))
					data = self.random_data_generator(bytes_sent)
			if isinstance(data, bytes):
				bytes_sent = len(data)

		start = time.perf_counter()
		headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(bytes_sent)}
		async with self.session.request(method, url=url, allow_redirects=False, data=data, headers=headers) as response:
			data_received = b""
			async for data in response.content.iter_chunked(64 * 1024):
				data_received += data
			bytes_received = len(data_received)
			end = time.perf_counter()
			error = None
			if response.status not in (200, 201, 204):
				error = f"{response.status} - {data!r}"
			if self.perftest.print_responses or error:
				if error:
					print(f"Error: {error}")
				else:
					print(f"Resonse: {response.status} - {bytes_received} bytes body")
			return (error, end - start, bytes_sent, bytes_received, end - start)

	def jsonrpc_request(self, method: str, params: list[Any] | None = None) -> dict[str, Any]:
		params = params or []
		for idx, param in enumerate(params):
			if isinstance(param, str) and param.startswith("{{random_data:"):
				size = int(param.split(":")[1].strip("}"))
				# TODO: more randomized data
				params[idx] = "o" * size
			if isinstance(param, str) and param.startswith("{file:"):
				filename = param.split(":")[1].strip("}")
				with open(filename, "r", encoding="utf-8") as file:  # pylint: disable=dotted-import-in-loop
					params[idx] = file.read()
		return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}

	async def execute_jsonrpc_request(self, request: dict[str, Any]) -> tuple[Any | None, Any, int, int]:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
		headers = {}

		if self.test_case.encoding == "json":
			headers["content-type"] = "application/json"
			data = await asyncio.get_event_loop().run_in_executor(executor, json.encode, request)
		elif self.test_case.encoding == "msgpack":
			headers["content-type"] = "application/msgpack"
			data = await asyncio.get_event_loop().run_in_executor(executor, msgpack.encode, request)
		else:
			raise ValueError(f"Invalid encoding: {self.test_case.encoding}")

		request_data_len = len(data)
		if self.test_case.compression:
			if self.test_case.compression == "lz4":
				data = await asyncio.get_event_loop().run_in_executor(executor, lz4.frame.compress, data, 0)
			elif self.test_case.compression == "deflate":
				data = await asyncio.get_event_loop().run_in_executor(executor, zlib.compress, data)
			elif self.test_case.compression == "gzip":
				data = await asyncio.get_event_loop().run_in_executor(executor, gzip.compress, data)
			else:
				raise ValueError(f"Invalid compression: {self.test_case.compression}")
			headers["content-encoding"] = self.test_case.compression
			headers["accept-encoding"] = self.test_case.compression
		else:
			headers["accept-encoding"] = ""

		response = None
		async with self.session.post(url=f"{self.perftest.base_url}/rpc", data=data, headers=headers) as http_response:
			body = await http_response.read()
			if "lz4" in http_response.headers.get("content-encoding", ""):
				body = await asyncio.get_event_loop().run_in_executor(executor, lz4.frame.decompress, body)
			error = None
			if http_response.status != 200:
				error = f"{http_response.status} - {body!r}"
			else:
				if http_response.headers.get("content-type") == "application/msgpack":
					response = await asyncio.get_event_loop().run_in_executor(executor, msgpack.decode, body)
				else:
					response = await asyncio.get_event_loop().run_in_executor(executor, json.decode, body)
				if response.get("error"):
					error = response["error"]

		if self.perftest.print_responses or error:
			if error:
				print(f"Error: {error}")
			else:
				print(f"Response: {http_response.status} - {body!r}")

		return response, error, request_data_len, len(body or "")

	async def jsonrpc(self, method: str, params: list[Any] | None = None) -> tuple[Optional[str], float, int, int, float]:
		params = params or []
		request = self.jsonrpc_request(method, params)
		start = time.perf_counter()
		_response, error, request_data_len, response_data_len = await self.execute_jsonrpc_request(request)
		end = time.perf_counter()
		return (error, end - start, request_data_len, response_data_len, end - start)

	async def messagebus_jsonrpc(self, method: str, params: list[Any] | None = None) -> tuple[Optional[str], float, int, int, float]:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
		params = params or []
		req = self.jsonrpc_request(method, params)
		messagebus_ws = await self.messagebus_ws()

		start = time.perf_counter()
		msg = JSONRPCRequestMessage(sender="@", channel="service:config:jsonrpc", rpc_id="1", method=req["method"], params=req["params"])
		data = msg.to_msgpack()

		if self.test_case.compression:
			if self.test_case.compression == "lz4":
				data = await asyncio.get_event_loop().run_in_executor(executor, lz4.frame.compress, data, 0)
			elif self.test_case.compression == "gzip":
				data = await asyncio.get_event_loop().run_in_executor(executor, gzip.compress, data)
			else:
				raise ValueError(f"Invalid compression: {self.test_case.compression}")

		data_len = len(data)
		await messagebus_ws.send_bytes(data)

		data = await messagebus_ws.receive_bytes()
		res_data_len = len(data)

		if self.test_case.compression:
			if self.test_case.compression == "lz4":
				data = await asyncio.get_event_loop().run_in_executor(executor, lz4.frame.decompress, data)
			elif self.test_case.compression == "gzip":
				data = await asyncio.get_event_loop().run_in_executor(executor, gzip.decompress, data)

		res = JSONRPCResponseMessage.from_msgpack(data)
		if res.ref_id != msg.id:
			raise RuntimeError(f"Received invalid response: {res}")

		end = time.perf_counter()

		error = None
		if res.error:
			error = res.error
		if self.perftest.print_responses or error:
			if error:
				print(f"Error: {error}")
			else:
				print(f"Response: {res.result}")

		return (error, end - start, data_len, res_data_len, end - start)


def main() -> None:
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument("-s", "--server", action="store", type=str, help="Configserver url / address")
	arg_parser.add_argument("-u", "--username", action="store", type=str, help="Auth username")
	arg_parser.add_argument("-p", "--password", action="store", type=str, nargs="?", const="", help="Auth password")
	arg_parser.add_argument("-c", "--clients", action="store", type=int, help="Number of concurrent clients")
	arg_parser.add_argument("-i", "--iterations", action="store", type=int, help="Number of test iterations")
	arg_parser.add_argument("-C", "--compression", action="store", type=str, help="Compression to use lz4/gzip/deflate/none")
	arg_parser.add_argument("-j", "--jsonrpc-methods", action="store", type=str, nargs="*", help="Execute jsonrpc methods")
	arg_parser.add_argument("-r", "--print-responses", action="store_true", default=None, help="Print server responses")
	arg_parser.add_argument("-l", "--load", action="store", nargs="+", metavar="FILE", help="Load test from FILE")
	arg_parser.add_argument("-w", "--write-results", action="store", metavar="FILE", help="Write results to FILE")
	arg_parser.add_argument("--bencher-results", action="store", metavar="FILE", help="Write bencher results to FILE")
	arg_parser.add_argument("--bencher-measure", action="store", metavar="MEASURE_SLUG", help="Add this measure to bencher results")

	arg_parser.add_argument(
		"--max-avg-seconds-per-request",
		action="store",
		type=float,
		help="Fail if average time per request exceeds this value (in seconds)",
		default=0,
	)
	arg_parser.add_argument(
		"--max-errors", action="store", type=int, help="Fail if number of request errors exceeds this value", default=-1
	)
	args = arg_parser.parse_args()
	kwargs = args.__dict__

	perftest = None

	if kwargs.get("password") == "":
		kwargs["password"] = getpass.getpass("Password: ")

	if kwargs.get("load"):
		for _file in kwargs["load"]:
			perftest = Perftest.from_file(_file, **dict(kwargs))
	else:
		del kwargs["load"]
		perftest = Perftest(**kwargs)

	uvloop.install()
	if perftest:
		asyncio.run(perftest.run())


if __name__ == "__main__":
	main()
	sys.exit(0)
