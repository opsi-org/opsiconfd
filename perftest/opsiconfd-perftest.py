#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:license: GNU Affero General Public License version 3
"""

import sys
import time
import uuid
import copy
import codecs
import getpass
import argparse
import asyncio
from urllib.parse import urlparse
import orjson
import aiohttp
import aiofiles
import shutil
import uvloop
import signal
import zlib
import gzip
import lz4.frame

class Perftest:
	def __init__(self, server, username, password, clients, iterations=1, print_responses=False, jsonrpc_methods=[], write_results=None):
		u = urlparse(server)
		self.base_url = "%s://%s:%d" % (u.scheme or 'https', u.hostname or u.path, u.port or 4447)
		self.username = username
		self.password = password
		self.num_clients = clients if clients and clients > 0 else 1
		self.iterations = iterations
		self.print_responses = print_responses
		self.test_cases = []
		self.write_results = write_results
		if self.write_results:
			open(self.write_results, "w").close()

		if jsonrpc_methods:
			requests = []
			for m in jsonrpc_methods:
				m = m.split('[', 1)
				method = m[0]
				params = []
				if len(m) > 1:
					params = orjson.loads('[' + m[1])
				requests.append(["jsonrpc", method, params])
			self.test_cases = [ TestCase(self, "JSONRPC", {"test": requests}) ]

	@classmethod
	def from_file(cls, filename, **kwargs):
		with codecs.open(filename, 'r', 'utf-8') as f:
			perftest = orjson.loads(f.read())
			for k, v in kwargs.items():
				if v is None or k == "load":
					continue
				perftest[k] = v
			test_cases = []
			if perftest.get("test_cases"):
				test_cases = copy.deepcopy(perftest["test_cases"])
				del perftest["test_cases"]
			pt = Perftest(**perftest)
			for test_case in test_cases:
				test_case["perftest"] = pt
				tc = TestCase(**test_case)
				pt.test_cases.append(tc)
			return pt

	async def run(self):
		for test_case in self.test_cases:
			await test_case.run()
	
	async def stop(self):
		for test_case in self.test_cases:
			await test_case.stop()

class TestCase:
	def __init__(self, perftest, name, requests, compression = None):
		self.perftest = perftest
		self.name = name
		self.requests = requests
		self.compression = compression
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
		width = shutil.get_terminal_size((80, 20))[0] # fallback: 100, 40
		if (width > 100):
			width = 100
		print("")
		print(f"===[ Running test '{self.name}' on '{self.perftest.base_url}' ]".ljust(width, '='))
		print(f" * {self.num_clients} concurrent clients")
		print(f" * {self.iterations} iterations")

		for i in range(self.num_clients):
			self.clients.append(Client(self))

		try:
			if self.requests.get("setup"):
				tasks = [ client.execute_requests(self.requests["setup"], add_results=False) for client in self.clients ]
				await asyncio.gather(*tasks)

			await asyncio.sleep(1)

			self.start = time.perf_counter()
			if self.requests.get("test"):
				for i in range(self.iterations):
					tasks = [ client.execute_requests(self.requests["test"]) for client in self.clients ]
					await asyncio.gather(*tasks, return_exceptions=False)
					if self._should_stop:
						break
			self.end = time.perf_counter()
			
			if self.requests.get("teardown"):
				tasks = [ client.execute_requests(self.requests["teardown"], add_results=False) for client in self.clients ]
				await asyncio.gather(*tasks)
		finally:
			tasks = [ client.cleanup() for client in self.clients ]
			await asyncio.gather(*tasks)
		
		print("")
		self.display_results()
		if self.perftest.write_results:
			self.write_results()
		print("")

	def add_result(self, error: None, seconds: float, bytes_sent: int, bytes_received: int):
		res = locals()
		del res["self"]
		#print(res)
		self.results.append(res)
		if len(self.results) % 10 == 0:
			sys.stdout.write('.')
			sys.stdout.flush()
		if len(self.results) % 500 == 0:
			sys.stdout.write('\n')
			sys.stdout.flush()

	def calc_results(self):
		r = {
			"total_seconds": self.end - self.start,
			"requests": 0,
			"errors": 0,
			"total_request_seconds": 0.0, 
			"bytes_sent": 0, 
			"bytes_received": 0,
			"avg_requests_per_second": 0,
			"min_seconds_per_request": 0,
			"avg_seconds_per_request": 0,
			"max_seconds_per_request": 0
		}

		for res in self.results:
			r["requests"] += 1
			if res["error"]:
				r["errors"] += 1
			r["total_request_seconds"] += res["seconds"]
			r["bytes_sent"] += res["bytes_sent"]
			r["bytes_received"] += res["bytes_received"]
			if r["min_seconds_per_request"] == 0 or r["min_seconds_per_request"] > res["seconds"]:
				r["min_seconds_per_request"] = res["seconds"]
			if r["max_seconds_per_request"] == 0 or r["max_seconds_per_request"] < res["seconds"]:
				r["max_seconds_per_request"] = res["seconds"]
		
		r["avg_seconds_per_request"] = r["total_request_seconds"] / r["requests"]
		r["avg_requests_per_second"] = r["requests"] / r["total_seconds"]
		r["avg_bytes_received_per_second"] = r["bytes_received"] / r["total_seconds"]
		r["avg_bytes_send_per_second"] = r["bytes_sent"] / r["total_seconds"]
		return r
	
	def write_results(self):
		with codecs.open(self.perftest.write_results, "a", "utf-8") as f:
			f.write(f"[{self.name}]\n")
			for k, v in self.calc_results().items():
				f.write(f"{k}={v}\n")
			f.write(f"\n")
	
	def display_results(self):
		r = self.calc_results()
		print("Results:")
		print(f" * Compression: {self.compression or 'none'}")
		print(f" * Requests: {r['requests']}")
		print(f" * Errors: {r['errors']}")
		print(f" * Total seconds: {r['total_seconds']:0.3f}")
		print(f" * Requests/second: {r['avg_requests_per_second']:0.3f}")
		print(f" * Request duration: min/avg/max {r['min_seconds_per_request']:0.3f}s/{r['avg_seconds_per_request']:0.3f}s/{r['max_seconds_per_request']:0.3f}s")
		print(f" * Bytes sent: {r['bytes_sent']/1000/1000:0.2f}MB ({r['avg_bytes_send_per_second']/1000/1000:0.2f}MB/s)")
		print(f" * Bytes received: {r['bytes_received']/1000/1000:0.2f}MB ({r['avg_bytes_received_per_second']/1000/1000:0.2f}MB/s)")
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
		if type(obj) is bytes:
			return obj
		if type(obj) is str:
			return obj.replace("{http_client_id}", self.http_client_id)
		if type(obj) is list:
			return  [self._fill_placeholders(o) for o in obj]
		return obj

	@property
	def session(self):
		if not self._session:
			self._session = aiohttp.ClientSession(
				connector=aiohttp.TCPConnector(ssl=False),
				auth=aiohttp.BasicAuth(login=self.perftest.username, password=self.perftest.password)
			)
		return self._session

	async def cleanup(self):
		if self._session:
			await self._session.close()
	
	async def random_data_generator(self, size=0, chunk_size=1*1000*1000):
		import tempfile
		tf = tempfile.TemporaryFile(mode="wb+")
		# TODO: more randomized data
		tf.write(b"o" * size)
		tf.seek(0)
		try:
			sent = 0
			while sent < size:
				data = tf.read(chunk_size)
				if not data:
					break
				yield data
				sent += len(data)
		finally:
			tf.close()

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
		size = 0
		if data:
			if type(data) is str:
				data = data.encode("utf-8")
			if data.startswith(b"{random_data:"):
				size = int(data.split(b':')[1].strip(b'}'))
				data = self.random_data_generator(size)
			else:
				size = len(data)
		
		headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}
		async with self.session.request(method, url=url, allow_redirects=False, data=data, headers=headers) as response:
			end = time.perf_counter()
			body = await response.text()
			error = None
			if response.status not in (200, 201, 204):
				error = f"{response.status} - {body}"
			if self.perftest.print_responses:
				print(f"{response.status} - {len(body or '')} bytes body")
			elif error:
				print(error)
			return (error, end - start, size, len(body or ''))
	
	async def jsonrpc(self, method, params=[]):
		for i in range(len(params)):
			if type(params[i]) is str and params[i].startswith("{random_data:"):
				size = int(params[i].split(':')[1].strip('}'))
				# TODO: more randomized data
				params[i] = "o" * size
		req = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": method,
			"params": params
		}

		headers = {"content-type": "application/json"}
		data = orjson.dumps(req)
		start = time.perf_counter()
		if self.test_case.compression:
			if self.test_case.compression == "lz4":
				data = await asyncio.get_event_loop().run_in_executor(None, lz4.frame.compress, data, 0)
			elif self.test_case.compression == "deflate":
				data = await asyncio.get_event_loop().run_in_executor(None, zlib.compress, data)
			elif self.test_case.compression == "gzip":
				data = await asyncio.get_event_loop().run_in_executor(None, gzip.compress, data)
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
				body = await asyncio.get_event_loop().run_in_executor(None, lz4.frame.decompress, body)
			error = None
			if response.status != 200:
				error = f"{response.status} - {body}"
			else:
				res = orjson.loads(body)
				if res.get('error'):
					error = res['error']
			if self.perftest.print_responses:
				print(f"{response.status} - {body}")
			elif error:
				print(error)
			
			return (error, end - start, len(data or ''), len(body or ''))

async def signal_handler(sig, loop, perftest):
	await perftest.stop()
	loop.stop()

def main():
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument("-s", "--server", action="store", type=str, help="Configserver url / address")
	arg_parser.add_argument("-u", "--username", action="store", type=str, help="Auth username")
	arg_parser.add_argument("-p", "--password", action="store", type=str, nargs='?', const="", help="Auth password")
	arg_parser.add_argument("-c", "--clients", action="store", type=int, help="Number of concurrent clients")
	arg_parser.add_argument("-i", "--iterations", action="store", type=int, help="Number of test iterations")
	arg_parser.add_argument("-j", "--jsonrpc-methods", action="store", type=str, nargs="*", help="Execute jsonrpc methods")
	arg_parser.add_argument("-r", "--print-responses", action="store_true", default=None, help="Print server responses")
	arg_parser.add_argument("-l", "--load", action="store", nargs='+', metavar="FILE", help="Load test from FILE")
	arg_parser.add_argument("-w", "--write-results", action="store", metavar="FILE", help="Write results to FILE")
	args = arg_parser.parse_args()
	kwargs = args.__dict__
	
	uvloop.install()
	loop = asyncio.get_event_loop()
	perftest = None

	if kwargs.get('password') == "":
		kwargs['password'] = getpass.getpass('Password: ')

	if kwargs.get('load'):
		for _file in kwargs['load']:
			perftest = Perftest.from_file(_file, **dict(kwargs))
	else:
		del kwargs["load"]
		perftest = Perftest(**kwargs)

	#loop.create_task(perftest.run())
	signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
	for sig in signals:
		loop.add_signal_handler(sig, lambda sig=sig: loop.create_task(signal_handler(sig, loop, perftest)))
	loop.run_until_complete(perftest.run())
	
if __name__ == '__main__':
	try:
		main()
	except Exception as e:
		raise
		#print(e, file=sys.stderr)
		#sys.exit(1)
sys.exit(0)
