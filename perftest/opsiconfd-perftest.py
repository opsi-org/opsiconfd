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

import sys
import time
import uuid
import copy
import codecs
import getpass
import argparse
import tempfile
import asyncio
from urllib.parse import urlparse
import shutil
import signal
import zlib
import gzip
from concurrent.futures import ProcessPoolExecutor

import uvloop
import orjson
import aiohttp
import lz4.frame  # type: ignore[import]
import msgpack  # type: ignore[import]

executor = ProcessPoolExecutor(max_workers=25)


class Perftest:  # pylint: disable=too-many-instance-attributes
	def __init__(
		self, server, username, password, clients, iterations=1, print_responses=False, jsonrpc_methods=None, write_results=None
	):  # pylint: disable=too-many-arguments
		url = urlparse(server)
		self.base_url = f"{url.scheme or 'https'}://{url.hostname or url.path}:{url.port or 4447}"
		self.username = username
		self.password = password
		self.num_clients = clients if clients and clients > 0 else 1
		self.iterations = iterations
		self.print_responses = print_responses
		self.test_cases = []
		self.write_results = write_results
		if self.write_results:
			with open(self.write_results, "wb"):
				pass

		if jsonrpc_methods:
			requests = []
			for meth in jsonrpc_methods:
				meth = meth.split("[", 1)
				method = meth[0]
				params = []
				if len(meth) > 1:
					params = orjson.loads("[" + meth[1])  # pylint: disable=no-member
				requests.append(["jsonrpc", method, params])
			self.test_cases = [TestCase(self, "JSONRPC", {"test": requests})]

	async def signal_handler(self, _sig):
		await self.stop()

	@classmethod
	def from_file(cls, filename, **kwargs):
		with codecs.open(filename, "r", "utf-8") as file:
			perftest = orjson.loads(file.read())  # pylint: disable=no-member
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

	async def run(self):
		loop = asyncio.get_event_loop()
		signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
		for sig in signals:
			loop.add_signal_handler(sig, lambda sig=sig: loop.create_task(self.signal_handler(sig)))

		for test_case in self.test_cases:
			await test_case.run()

	async def stop(self):
		for test_case in self.test_cases:
			await test_case.stop()


class TestCase:  # pylint: disable=too-many-instance-attributes
	def __init__(self, perftest, name, requests, compression=None, encoding="json"):  # pylint: disable=too-many-arguments
		self.perftest = perftest
		self.name = name
		self.requests = requests
		self.compression = compression
		self.encoding = encoding
		self.clients = []
		self.results = []
		self.start = None
		self.end = None
		self._should_stop = False

	@property
	def num_clients(self):
		return self.perftest.num_clients

	@property
	def iterations(self):
		return self.perftest.iterations

	async def stop(self):
		self._should_stop = True
		if self.start:
			while not self.end:
				await asyncio.sleep(0.1)

	async def run(self):
		width = shutil.get_terminal_size((80, 20))[0]  # fallback: 100, 40
		width = min(width, 100)
		print("")
		print(f"===[ Running test '{self.name}' on '{self.perftest.base_url}' ]".ljust(width, "="))
		print(f" * {self.num_clients} concurrent clients")
		print(f" * {self.iterations} iterations")

		for _i in range(self.num_clients):
			self.clients.append(Client(self))

		try:
			if self.requests.get("setup"):
				tasks = [client.execute_requests(self.requests["setup"], add_results=False) for client in self.clients]
				await asyncio.gather(*tasks)

			await asyncio.sleep(1)

			self.start = time.perf_counter()
			if self.requests.get("test"):
				for _i in range(self.iterations):
					tasks = [client.execute_requests(self.requests["test"]) for client in self.clients]
					await asyncio.gather(*tasks, return_exceptions=False)
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
		print("")

	def add_result(self, error: None, seconds: float, bytes_sent: int, bytes_received: int):
		res = {"error": error, "seconds": seconds, "bytes_sent": bytes_sent, "bytes_received": bytes_received}
		self.results.append(res)
		if len(self.results) % 10 == 0:
			sys.stdout.write(".")
			sys.stdout.flush()
		if len(self.results) % 500 == 0:
			sys.stdout.write("\n")
			sys.stdout.flush()

	def calc_results(self):
		result = {
			"total_seconds": self.end - self.start,
			"requests": 0,
			"errors": 0,
			"total_request_seconds": 0.0,
			"bytes_sent": 0,
			"bytes_received": 0,
			"avg_requests_per_second": 0,
			"min_seconds_per_request": 0,
			"avg_seconds_per_request": 0,
			"max_seconds_per_request": 0,
		}

		for res in self.results:
			result["requests"] += 1
			if res["error"]:
				result["errors"] += 1
			result["total_request_seconds"] += res["seconds"]
			result["bytes_sent"] += res["bytes_sent"]
			result["bytes_received"] += res["bytes_received"]
			if result["min_seconds_per_request"] == 0 or result["min_seconds_per_request"] > res["seconds"]:
				result["min_seconds_per_request"] = res["seconds"]
			if result["max_seconds_per_request"] == 0 or result["max_seconds_per_request"] < res["seconds"]:
				result["max_seconds_per_request"] = res["seconds"]

		result["avg_seconds_per_request"] = result["total_request_seconds"] / result["requests"]
		result["avg_requests_per_second"] = result["requests"] / result["total_seconds"]
		result["avg_bytes_received_per_second"] = result["bytes_received"] / result["total_seconds"]
		result["avg_bytes_send_per_second"] = result["bytes_sent"] / result["total_seconds"]
		return result

	def write_results(self):
		with codecs.open(self.perftest.write_results, "a", "utf-8") as file:
			file.write(f"[{self.name}]\n")
			for key, val in self.calc_results().items():
				file.write(f"{key}={val}\n")
			file.write("\n")

	def display_results(self):
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
		)  # pylint: disable=line-too-long
		print(f" * Bytes sent: {res['bytes_sent']/1000/1000:0.2f}MB ({res['avg_bytes_send_per_second']/1000/1000:0.2f}MB/s)")
		print(f" * Bytes received: {res['bytes_received']/1000/1000:0.2f}MB ({res['avg_bytes_received_per_second']/1000/1000:0.2f}MB/s)")
		print("")


class Client:
	def __init__(self, test_case):
		self.test_case = test_case
		self._session = None
		self.http_client_id = str(uuid.uuid4())

	@property
	def perftest(self):
		return self.test_case.perftest

	def _fill_placeholders(self, obj):
		if isinstance(obj, bytes):
			return obj
		if isinstance(obj, str):
			return obj.replace("{http_client_id}", self.http_client_id)
		if isinstance(obj, list):
			return [self._fill_placeholders(o) for o in obj]
		return obj

	@property
	def session(self):
		if not self._session:
			self._session = aiohttp.ClientSession(
				connector=aiohttp.TCPConnector(ssl=False),
				auth=aiohttp.BasicAuth(login=self.perftest.username, password=self.perftest.password),
				cookie_jar=aiohttp.CookieJar(unsafe=True),
			)
		return self._session

	async def cleanup(self):
		if self._session:
			await self._session.close()

	@staticmethod
	async def random_data_generator(size=0, chunk_size=1000 * 1000):
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

	async def execute_requests(self, requests, add_results=True):
		for request in requests:
			method = getattr(self, request[0])
			params = self._fill_placeholders(request[1:])
			result = await method(*params)
			if add_results:
				self.test_case.add_result(*result)

	async def webdav(self, method, filename, data=None):
		url = f"{self.perftest.base_url}/repository/{filename}"
		start = time.perf_counter()
		bytes_sent = 0
		if data:
			if isinstance(data, str):
				data = data.encode("utf-8")
			if data.startswith(b"{random_data:"):
				bytes_sent = int(data.split(b":")[1].strip(b"}"))
				data = self.random_data_generator(bytes_sent)
			else:
				bytes_sent = len(data)

		headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(bytes_sent)}
		async with self.session.request(method, url=url, allow_redirects=False, data=data, headers=headers) as response:
			data = None
			bytes_received = 0
			async for data in response.content.iter_chunked(64 * 1024):
				bytes_received += len(data)
			end = time.perf_counter()
			error = None
			if response.status not in (200, 201, 204):
				error = f"{response.status} - {data}"
			if self.perftest.print_responses:
				print(f"{response.status} - {bytes_received} bytes body")
			elif error:
				print(error)
			return (error, end - start, bytes_sent, bytes_received)

	async def jsonrpc(self, method, params=None):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
		params = params or []
		for idx, param in enumerate(params):
			if isinstance(param, str) and param.startswith("{random_data:"):
				size = int(param.split(":")[1].strip("}"))
				# TODO: more randomized data
				params[idx] = "o" * size
			if isinstance(param, str) and param.startswith("{file:"):
				filename = param.split(":")[1].strip("}")
				with codecs.open(filename, "r", "utf-8") as file:
					params[idx] = file.read()
		req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
		headers = {}
		if self.test_case.encoding == "json":
			headers["content-type"] = "application/json"
			data = await asyncio.get_event_loop().run_in_executor(executor, orjson.dumps, req)  # pylint: disable=no-member
		elif self.test_case.encoding == "msgpack":
			headers["content-type"] = "application/msgpack"
			data = await asyncio.get_event_loop().run_in_executor(executor, msgpack.dumps, req)
		else:
			raise ValueError(f"Invalid encoding: {self.test_case.encoding}")

		data_len = len(data)
		start = time.perf_counter()
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

		async with self.session.post(url=f"{self.perftest.base_url}/rpc", data=data, headers=headers) as response:
			end = time.perf_counter()
			body = await response.read()
			if "lz4" in response.headers.get("content-encoding", ""):
				body = await asyncio.get_event_loop().run_in_executor(executor, lz4.frame.decompress, body)
			error = None
			if response.status != 200:
				error = f"{response.status} - {body}"
			else:
				res = None
				if response.headers.get("content-type") == "application/msgpack":
					res = await asyncio.get_event_loop().run_in_executor(executor, msgpack.loads, body)
				else:
					res = await asyncio.get_event_loop().run_in_executor(executor, orjson.loads, body)  # pylint: disable=no-member

				if res.get("error"):
					error = res["error"]
			if self.perftest.print_responses:
				print(f"{response.status} - {body}")
			elif error:
				print(error)

			return (error, end - start, data_len, len(body or ""))


def main():
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument("-s", "--server", action="store", type=str, help="Configserver url / address")
	arg_parser.add_argument("-u", "--username", action="store", type=str, help="Auth username")
	arg_parser.add_argument("-p", "--password", action="store", type=str, nargs="?", const="", help="Auth password")
	arg_parser.add_argument("-c", "--clients", action="store", type=int, help="Number of concurrent clients")
	arg_parser.add_argument("-i", "--iterations", action="store", type=int, help="Number of test iterations")
	arg_parser.add_argument("-j", "--jsonrpc-methods", action="store", type=str, nargs="*", help="Execute jsonrpc methods")
	arg_parser.add_argument("-r", "--print-responses", action="store_true", default=None, help="Print server responses")
	arg_parser.add_argument("-l", "--load", action="store", nargs="+", metavar="FILE", help="Load test from FILE")
	arg_parser.add_argument("-w", "--write-results", action="store", metavar="FILE", help="Write results to FILE")
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
	asyncio.run(perftest.run())


if __name__ == "__main__":
	main()
	sys.exit(0)
