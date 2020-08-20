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

import os
import re
import time
import datetime
import asyncio
import threading
import psutil
import json
import copy
import redis
from contextvars import ContextVar
from typing import Dict, List
from ctypes import c_long
import yappi
from yappi import YFuncStats
from redis import ResponseError as RedisResponseError
from aredis.exceptions import ResponseError 

from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .logging import logger
from .worker import get_redis_client, get_metrics_collector, \
	contextvar_request_id, contextvar_client_address, contextvar_server_address, contextvar_server_timing
from .config import config
from .utils import Singleton, get_worker_processes, get_node_name, get_worker_num
from .grafana import GrafanaPanelConfig

def get_yappi_tag() -> int:
	return int(contextvar_request_id.get() or -1)


def setup_metric_downsampling() -> None:

	redis_client = redis.StrictRedis.from_url(config.redis_internal_url)

	for metric in metrics_registry.get_metrics():
		if not metric.downsampling or metric.subject != "worker":
			continue
		for worker in range(1, config.workers+1):
			node_name = get_node_name()
			worker_num = worker
			logger.debug("worker: %s:%s", node_name, worker_num)
			orig_key = metric.redis_key.format(node_name=node_name, worker_num=worker_num)
			cmd = f"TS.CREATE {orig_key} RETENTION {metric.retention} LABELS node_name {node_name} worker_num {worker_num}"
			logger.debug("REDIS CMD: %s", cmd)
			try:
				redis_client.execute_command(cmd)
			except RedisResponseError as e:
				if str(e) != "TSDB: key already exists":
					raise RedisResponseError(e)
			
			for rule in metric.downsampling:
				key = metric.redis_key.format(node_name=node_name, worker_num=worker_num)
				key = f"{key}:{rule[0]}"
				retention_time = rule[1]
				cmd = f"TS.CREATE {key} RETENTION {retention_time} LABELS node_name {node_name} worker_num {worker_num}"
				logger.debug("REDIS CMD: %s", cmd)
				try:
					redis_client.execute_command(cmd)
				except RedisResponseError as e: 
					if str(e) != "TSDB: key already exists":
						raise RedisResponseError(e)
				
				time_bucket = get_time_bucket(rule[0])
				cmd = f"TS.CREATERULE {orig_key} {key} AGGREGATION {metric.aggregation} {time_bucket}"
				logger.debug("REDIS CMD: %s", cmd)
				try:
					redis_client.execute_command(cmd)
				except RedisResponseError as e: 
					if str(e) != "TSDB: the destination key already has a rule":
						raise RedisResponseError(e)
				

def get_time_bucket(interval: str ) -> int:
	time_buckets = {
		"minute": 60 * 1000,
		"hour": 3600 * 1000,
		"day": 24 * 3600 * 1000,
		"week": 7 * 24 * 3600 * 1000,
		"month": 30 * 24 * 3600 * 1000,
		"year": 365 * 24 * 3600 * 1000
	}
	time_bucket = time_buckets.get(interval)
	if time_bucket is None:
		raise ValueError(f"Invalid interval: {interval}")
	return time_bucket

class Metric:
	def __init__(self, id: str, name: str, vars: List[str] = [], aggregation: str = "sum", retention: int = 0, zero_if_missing: bool = True,
				subject: str = "worker", server_timing_header_factor: int = None, grafana_config: GrafanaPanelConfig = None, downsampling: List = None):
		assert aggregation in ("sum", "avg")
		assert subject in ("worker", "client")
		self.id = id
		self.name = name
		self.vars = vars
		self.aggregation = aggregation
		self.retention = retention
		self.zero_if_missing = zero_if_missing
		self.subject = subject
		self.server_timing_header_factor = server_timing_header_factor
		self.grafana_config = grafana_config
		self.redis_key = self.redis_key_prefix = f"opsiconfd:stats:{id}"
		self.downsampling = downsampling
		for var in self.vars:
			self.redis_key += ":{" + var + "}"
		name_regex = self.name
		for var in vars:
			name_regex = name_regex.replace('{' + var + '}', f"(?P<{var}>\S+)")
		self.name_regex = re.compile(name_regex)

	def get_redis_key(self, **kwargs):
		if not kwargs:
			return self.redis_key_prefix
		return self.redis_key.format(**kwargs)
	
	def get_name(self, **kwargs):
		return self.name.format(**kwargs)
	
	def get_vars_by_redis_key(self, redis_key):
		vars = {}
		if self.vars:
			values = redis_key[len(self.redis_key_prefix)+1:].split(':')
			for i, value in enumerate(values):
				vars[self.vars[i]] = value
		return vars
	
	def get_name_by_redis_key(self, redis_key):
		vars = self.get_vars_by_redis_key(redis_key)
		return self.get_name(**vars)

	def get_vars_by_name(self, name):
		return self.name_regex.fullmatch(name).groupdict()

class MetricsRegistry(metaclass=Singleton):
	def __init__(self):
		self._metrics_by_id = {}
	
	def register(self, *metric):
		for m in metric:
			self._metrics_by_id[m.id] = m

	def get_metric_ids(self):
		return list(self._metrics_by_id)
	
	def get_metrics(self, subject: str = None):
		for metric in self._metrics_by_id.values():
			if not subject or subject == metric.subject:
				yield metric

	def get_metric_by_id(self, id):
		if id in self._metrics_by_id:
			return self._metrics_by_id[id]
		raise ValueError(f"Metric with id '{id}' not found")

	def get_metric_by_name(self, name):
		for metric in self._metrics_by_id.values():
			match = metric.name_regex.fullmatch(name)
			if match:
				return metric
		raise ValueError(f"Metric with name '{name}' not found")
	
	def get_metric_by_redis_key(self, redis_key):
		for metric in self._metrics_by_id.values():
			if redis_key == metric.redis_key_prefix or redis_key.startswith(metric.redis_key_prefix + ':'):
				return metric
		raise ValueError(f"Metric with redis key '{redis_key}' not found")

metrics_registry = MetricsRegistry()

metrics_registry.register(
	Metric(
		id="worker:mem_allocated",
		name="Memory usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		aggregation="avg",
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Memory usage", units=["decbytes"], stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:cpu_percent",
		name="CPU usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		aggregation="avg",
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="CPU usage", units=["percent"], decimals=1, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:num_threads",
		name="Threads of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Threads", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:num_filehandles",
		name="Filehandles of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Filehandles", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:num_http_request",
		name="HTTP requests of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP requests", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:http_response_bytes",
		name="HTTP response size of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP response size", units=["decbytes"], stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:http_request_duration",
		name="Duration of HTTP requests processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		aggregation="avg",
		retention=2 * 3600 * 1000,
		zero_if_missing=False,
		subject="worker",
		grafana_config=GrafanaPanelConfig(type="heatmap", title="Duration of HTTP requests", units=["s"], decimals=0),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="client:num_http_request",
		name="HTTP requests of Client {client_addr}",
		vars=["client_addr"],
		retention=24 * 3600 * 1000,
		subject="client",
		grafana_config=GrafanaPanelConfig(title="Client requests", units=["short"], decimals=0, stack=False)
	)
)


class MetricsCollector():
	def __init__(self, interval: int = 5):
		self._interval = interval
		self._node_name = get_node_name()
		self._worker_num = get_worker_num()
		self._proc = None
		self._values = {}
		self._values_lock = asyncio.Lock()
		self._last_timestamp = 0
	
	def _get_timestamp(self) -> int:
		# return unix timestamp in millis
		# milliseconds since Jan 01 1970. (UTC)
		return int(time.time() * 1000)
		#return int(round(datetime.datetime.utcnow().timestamp())*1000)
	
	async def _fetch_values(self):
		if not self._proc:
			self._proc = psutil.Process()
		await self.add_value("worker:mem_allocated", self._proc.memory_info().rss, {"node_name": get_node_name(), "worker_num": get_worker_num()})
		await self.add_value("worker:cpu_percent", self._proc.cpu_percent(), {"node_name": get_node_name(), "worker_num": get_worker_num()})
		await self.add_value("worker:num_threads", self._proc.num_threads(), {"node_name": get_node_name(), "worker_num": get_worker_num()})
		await self.add_value("worker:num_filehandles", self._proc.num_fds(), {"node_name": get_node_name(), "worker_num": get_worker_num()})

	async def main_loop(self):		
		while True:
			cmd = None
		
			try:
				await self._fetch_values()
				timestamp = self._get_timestamp()
		
				for metric in metrics_registry.get_metrics():
					if not metric.id in self._values:
						continue
					if metric.subject == "client":
						labels = {}
						for addr in self._values[metric.id]:
							value = 0
							count = 0
							async with self._values_lock:
								values = self._values[metric.id].get(addr, {})
								logger.debug("MetricsCollector values: %s ", values)
								if not values and not metric.zero_if_missing:
									continue
								for ts in list(values):
									if ts <= timestamp:
										count += 1
										value += values[ts]
										del values[ts]
							if metric.aggregation == "avg" and count > 0:
								value /= count

							labels["client_addr"] = addr
							cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
							logger.debug(cmd)
							await self._execute_redis_command(cmd)
					else:
						value = 0
						count = 0
						async with self._values_lock:
							for key in self._values.get(metric.id, {}):
								values = self._values[metric.id].get(key, {})
							if not values and not metric.zero_if_missing:
								continue
							for ts in list(values):
								if ts <= timestamp:
									count += 1
									value += values[ts]
									del values[ts]
						if metric.aggregation == "avg" and count > 0:
							value /= count
						labels = {}
						label_values = None
						for key in self._values[metric.id]:
							if label_values == None:
								label_values = (key.split(":"))
							else:
								label_values.append(key.split(":"))
						for idx, var in enumerate(metric.vars):
							labels[var] = label_values[idx]
						cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
						logger.debug("CMD: %s", cmd)
						await self._execute_redis_command(cmd)

			except Exception as exc:
				err = str(exc)
				if cmd:
					err += f" while executing redis command: {cmd}"
				logger.error(err, exc_info=True)
				if err.lower().startswith("unknown command"):
					logger.error("RedisTimeSeries module missing, metrics collector ending")
					break
			await asyncio.sleep(self._interval)

	def _redis_ts_cmd(self, metric: Metric, cmd: str, value: float, timestamp: int = None, **labels):
		timestamp = timestamp or "*"
		l_labels = []
		
		for key in labels:
			l_labels.extend([key, labels[key]])
		if cmd == "ADD":
			cmd = ["TS.ADD", metric.get_redis_key(**labels), timestamp, value, "RETENTION", metric.retention, "LABELS"] + l_labels
		elif cmd == "INCRBY":
			cmd = ["TS.INCRBY", metric.get_redis_key(**labels), value, timestamp, "RETENTION", metric.retention, "LABELS"] + l_labels
		else:
			raise ValueError(f"Invalid command {cmd}")
		return " ".join([ str(x) for x in cmd ])

	async def _execute_redis_command(self, cmd, max_tries=2):
		if type(cmd) is list:
			cmd = " ".join([ str(x) for x in cmd ])
		logger.debug("Executing redis command: %s", cmd)
		for trynum in range(1, max_tries + 1):
			try:
				redis = await get_redis_client()
				return await redis.execute_command(cmd)
			except ResponseError:
				if trynum >= max_tries:
					raise
				# TODO: Remove or refactor, timestamp is not always cmd[2]
				cmd = cmd.split(" ")
				cmd[2] = timestamp = self._get_timestamp() + 1
				cmd = " ".join([ str(x) for x in cmd ])
	
	#def add_value(self, metric: Metric, value: float, timestamp: int = None, **kwargs):
	async def add_value(self, metric_id: str, value: float, labels: dict = {}, timestamp: int = None):
		metric = metrics_registry.get_metric_by_id(metric_id)
		# logger.debug("add_value metric_id: %s, labels: %s ", metric_id, labels)
		key_string = ""
		for var in metric.vars:
			if not key_string: 
				key_string = labels[var]
			else:
				key_string = f"{key_string}:{labels[var]}"
		# logger.debug(f"KEYSTRING: {key_string}")	
		if metric.server_timing_header_factor:
			server_timing = contextvar_server_timing.get()
			if type(server_timing) is dict:
				# Only if dict (initialized)
				server_timing[metric_id.split(':')[-1]] = value * metric.server_timing_header_factor
				contextvar_server_timing.set(server_timing)
		if not timestamp:
			timestamp = self._get_timestamp()
		async with self._values_lock:
			# key = json.dumps(kwargs, sort_keys=True)
			if not metric_id in self._values:
				self._values[metric_id] = {}
			if not key_string in self._values[metric_id]:
				self._values[metric_id][key_string] = {}
			if not timestamp in self._values[metric_id][key_string]:
				self._values[metric_id][key_string][timestamp] = 0
			self._values[metric_id][key_string][timestamp] += value
			# logger.debug("VALUES end add_value: %s", self._values)

class StatisticsMiddleware(BaseHTTPMiddleware):
	def __init__(self, app: ASGIApp, profiler_enabled=False, log_func_stats=False) -> None:
		super().__init__(app)
		
		self._profiler_enabled = profiler_enabled
		self._log_func_stats = log_func_stats
		self._profile_methods: Dict[str, str] = {
			"BackendManager._executeMethod": "backend",
			"MySQL.execute": "mysql",
			"Response.render": "render",
			#"serialize": "opsi_serialize",
			#"deserialize": "opsi_deserialize",
		}
		if self._profiler_enabled:
			yappi.set_tag_callback(get_yappi_tag)
			yappi.set_clock_type("wall")
			# TODO: Schedule some kind of periodic profiler cleanup with clear_stats()
			yappi.start()

	def yappi(self, scope):
		# https://github.com/sumerc/yappi/blob/master/doc/api.md

		tag = get_yappi_tag()
		if tag == -1:
			return
		
		#yappi.get_func_stats(filter={"tag": tag}).sort('ttot', sort_order="asc").debug_print()
		max_stats = 500
		if self._log_func_stats:
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------")
			logger.essential(f"{scope['request_id']} - {scope['client'][0]} - {scope['method']} {scope['path']}")
			logger.essential(f"{'module':<45} | {'function':<60} | {'calls':>5} | {'total time':>10}")
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------")
			func_stats = yappi.get_func_stats(filter={"tag": tag}).sort("ttot", sort_order="desc")
			for stat_num, stat in enumerate(func_stats):
				module = re.sub(r".*(site-packages|python3\.\d|python-opsi)/", "", stat.module)
				logger.essential(f"{module:<45} | {stat.name:<60} | {stat.ncall:>5} |   {stat.ttot:0.6f}")
				if stat_num >= max_stats:
					break
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------")

		func_stats: Dict[str, YFuncStats] = {
			stat_name: yappi.get_func_stats(filter={"name": function, "tag": tag})
			for function, stat_name in self._profile_methods.items()
		}
		server_timing = {}
		for stat_name, stats in func_stats.items():
			if not stats.empty():
				server_timing[stat_name] = stats.pop().ttot * 1000
		return server_timing

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		logger.trace(f"StatisticsMiddleware {scope}")

		if scope["type"] not in ("http", "websocket"):
			await self.app(scope, receive, send)
			return
		
		start = time.perf_counter()
		request_id = id(scope)
		# Longs on Windows are only 32 bits, but memory adresses on 64 bit python are 64 bits
		request_id = abs(c_long(request_id).value) # Ensure it fits inside a long, truncating if necessary
		scope['request_id'] = request_id
		contextvar_request_id.set(request_id)
		contextvar_client_address.set(scope["client"][0])
		contextvar_server_address.set(scope["server"][0])
		contextvar_server_timing.set({})

		# logger.debug("Client Addr: %s", contextvar_client_address.get())
		async def send_wrapper(message: Message) -> None:
			await get_metrics_collector().add_value("worker:num_http_request", 1, {"node_name": get_node_name(), "worker_num": get_worker_num()})
			await get_metrics_collector().add_value("client:num_http_request", 1, {"client_addr": contextvar_client_address.get()})

			if message["type"] == "http.response.start":
				headers = MutableHeaders(scope=message)
				server_timing = contextvar_server_timing.get() or {}
				if self._profiler_enabled:
					server_timing.update(self.yappi(scope))
				if server_timing:
					server_timing = [f"{k};dur={v:.3f}"	for k, v in server_timing.items()]
					headers.append("Server-Timing", ','.join(server_timing))
			logger.trace(message)
			await send(message)
			end = time.perf_counter()
			if scope["type"] == "http":
				if "body" in message:
					await get_metrics_collector().add_value(
						"worker:http_response_bytes",
						len(message['body']),
						{"node_name": get_node_name(), "worker_num": get_worker_num()}
					)
				await get_metrics_collector().add_value(
					"worker:http_request_duration",
					end - start,
					{"node_name": get_node_name(), "worker_num": get_worker_num()}
				)
				
		await self.app(scope, receive, send_wrapper)