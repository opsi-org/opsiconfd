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

import re
import time
import asyncio
from typing import Dict, List
import psutil

import yappi
from yappi import YFuncStats
from redis import ResponseError as RedisResponseError
from aredis.exceptions import ResponseError

from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .logging import logger
from .worker import (
	get_redis_client, get_metrics_collector,
	contextvar_request_id, contextvar_client_address, contextvar_server_timing
)
from .config import config
from .utils import (
	Singleton, get_node_name, get_worker_num, get_redis_connection
)
from .grafana import GrafanaPanelConfig

def get_yappi_tag() -> int:
	return int(contextvar_request_id.get() or -1)


def setup_metric_downsampling() -> None: # pylint: disable=too-many-locals, too-many-branches

	redis_client = get_redis_connection(config.redis_internal_url)

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
			except RedisResponseError as err:
				if str(err) != "TSDB: key already exists":
					raise RedisResponseError(err) # pylint: disable=raise-missing-from

			cmd = f"TS.INFO {orig_key}"
			info = redis_client.execute_command(cmd)
			existing_rules = {}
			rules = []
			for idx, val in enumerate(info):
				if isinstance(val, bytes):
					if "rules" in val.decode("utf8"):
						rules = info[idx+1]
						break
			for rule in rules:
				rule_name = rule[0].decode("utf8").split(":")[-1]
				existing_rules[rule_name] = {"retention": rule[1], "aggregation": rule[2].decode("utf8")}
			for rule in metric.downsampling:
				key = metric.redis_key.format(node_name=node_name, worker_num=worker_num)
				key = f"{key}:{rule[0]}"
				retention_time = rule[1]
				cmd = f"TS.CREATE {key} RETENTION {retention_time} LABELS node_name {node_name} worker_num {worker_num}"
				try:
					redis_client.execute_command(cmd)
				except RedisResponseError as err:
					if str(err) != "TSDB: key already exists":
						raise RedisResponseError(err) # pylint: disable=raise-missing-from

				if rule[0] in existing_rules.keys():
					old_rule = existing_rules.get(rule[0])
					if get_time_bucket(rule[0]) != old_rule.get("retention") or metric.aggregation.lower() != old_rule.get("aggregation").lower():
						cmd = f"TS.DELETERULE {orig_key} {key}"
						redis_client.execute_command(cmd)

				time_bucket = get_time_bucket(rule[0])
				cmd = f"TS.CREATERULE {orig_key} {key} AGGREGATION {metric.aggregation} {time_bucket}"
				logger.debug("REDIS CMD: %s", cmd)
				try:
					redis_client.execute_command(cmd)
				except RedisResponseError as err:
					if str(err) != "TSDB: the destination key already has a rule":
						raise RedisResponseError(err) # pylint: disable=raise-missing-from


time_buckets = {
	"minute": 60 * 1000,
	"hour": 3600 * 1000,
	"day": 24 * 3600 * 1000,
	"week": 7 * 24 * 3600 * 1000,
	"month": 30 * 24 * 3600 * 1000,
	"year": 365 * 24 * 3600 * 1000
}

def get_time_bucket(interval: str ) -> int:
	time_bucket = time_buckets.get(interval)
	if time_bucket is None:
		raise ValueError(f"Invalid interval: {interval}")
	return time_bucket


def get_time_bucket_name(time: int) -> str: # pylint: disable=redefined-outer-name
	time_bucket_name = None
	for name, t in time_buckets.items(): # pylint: disable=invalid-name
		if time >= t:
			time_bucket_name = name
	return time_bucket_name

class Metric: # pylint: disable=too-many-instance-attributes
	def __init__(self, id: str, name: str, vars: List[str] = [], aggregation: str = "avg", retention: int = 0, zero_if_missing: bool = True, # pylint: disable=too-many-arguments, redefined-builtin, dangerous-default-value
				subject: str = "worker", server_timing_header_factor: int = None, grafana_config: GrafanaPanelConfig = None, downsampling: List = None):
		assert aggregation in ("sum", "avg")
		assert subject in ("worker", "client")
		self.id = id # pylint: disable=invalid-name
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
			name_regex = name_regex.replace('{' + var + '}', f"(?P<{var}>\S+)") # pylint: disable=anomalous-backslash-in-string
		self.name_regex = re.compile(name_regex)

	def get_redis_key(self, **kwargs):
		if not kwargs:
			return self.redis_key_prefix
		return self.redis_key.format(**kwargs)

	def get_name(self, **kwargs):
		return self.name.format(**kwargs)

	def get_vars_by_redis_key(self, redis_key):
		vars = {} # pylint: disable=redefined-builtin
		if self.vars:
			values = redis_key[len(self.redis_key_prefix)+1:].split(':')
			for i, value in enumerate(values):
				vars[self.vars[i]] = value
		return vars

	def get_name_by_redis_key(self, redis_key):
		vars = self.get_vars_by_redis_key(redis_key) # pylint: disable=redefined-builtin
		return self.get_name(**vars)

	def get_vars_by_name(self, name):
		return self.name_regex.fullmatch(name).groupdict()

class MetricsRegistry(metaclass=Singleton):
	def __init__(self):
		self._metrics_by_id = {}

	def register(self, *metric):
		for m in metric: # pylint: disable=invalid-name
			self._metrics_by_id[m.id] = m

	def get_metric_ids(self):
		return list(self._metrics_by_id)

	def get_metrics(self, subject: str = None):
		for metric in self._metrics_by_id.values():
			if not subject or subject == metric.subject:
				yield metric

	def get_metric_by_id(self, id): # pylint: disable=redefined-builtin, invalid-name
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
		id="worker:avg_mem_allocated",
		name="Average memory usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Memory usage", units=["decbytes"], stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_cpu_percent",
		name="Average CPU usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="CPU usage", units=["percent"], decimals=1, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_thread_number",
		name="Average threads of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Threads", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_filehandle_number",
		name="Average filehandles of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Filehandles", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_http_request_number",
		name="Average HTTP requests of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP requests", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_http_response_bytes",
		name="Average HTTP response size of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP response size", units=["decbytes"], stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_http_request_duration",
		name="Average duration of HTTP requests processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		zero_if_missing=False,
		subject="worker",
		grafana_config=GrafanaPanelConfig(type="heatmap", title="Duration of HTTP requests", units=["s"], decimals=0),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="client:sum_http_request",
		name="HTTP requests of Client {client_addr}",
		vars=["client_addr"],
		aggregation="sum",
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

	def _get_timestamp(self) -> int: # pylint: disable=no-self-use
		# return unix timestamp in millis
		# milliseconds since Jan 01 1970. (UTC)
		return int(time.time() * 1000)
		#return int(round(datetime.datetime.utcnow().timestamp())*1000)

	async def _fetch_values(self):
		if not self._proc:
			self._proc = psutil.Process()
		loop = asyncio.get_event_loop()
		loop.create_task(
			self.add_value("worker:avg_mem_allocated", self._proc.memory_info().rss, {"node_name": get_node_name(), "worker_num": get_worker_num()})
		)
		loop.create_task(
			self.add_value("worker:avg_cpu_percent", self._proc.cpu_percent(), {"node_name": get_node_name(), "worker_num": get_worker_num()})
		)
		loop.create_task(
			self.add_value("worker:avg_thread_number", self._proc.num_threads(), {"node_name": get_node_name(), "worker_num": get_worker_num()})
		)
		loop.create_task(
			self.add_value("worker:avg_filehandle_number", self._proc.num_fds(), {"node_name": get_node_name(), "worker_num": get_worker_num()})
		)

	async def main_loop(self): # pylint: disable=too-many-statements, too-many-branches, too-many-locals
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
						for addr in list(self._values[metric.id]):
							value = 0
							count = 0
							async with self._values_lock:
								values = self._values[metric.id].get(addr, {})
								logger.debug("MetricsCollector values: %s ", values)
								if not values and not metric.zero_if_missing:
									continue
								for ts in list(values): # pylint: disable=invalid-name
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
						values = None
						async with self._values_lock:
							for key in self._values.get(metric.id, {}):
								values = self._values[metric.id].get(key, {})
							if not values and not metric.zero_if_missing:
								continue
							for ts in list(values): # pylint: disable=invalid-name
								if ts <= timestamp:
									count += 1
									value += values[ts]
									del values[ts]
						if metric.aggregation == "avg" and count > 0:
							value /= count
						labels = {}
						label_values = None
						for key in self._values[metric.id]:
							if label_values is None:
								label_values = (key.split(":"))
							else:
								label_values.append(key.split(":"))
						for idx, var in enumerate(metric.vars):
							labels[var] = label_values[idx]
						cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
						logger.debug("CMD: %s", cmd)
						await self._execute_redis_command(cmd)

			except Exception as exc: # pylint: disable=broad-except
				err = str(exc)
				if cmd:
					err += f" while executing redis command: {cmd}"
				logger.error(err, exc_info=True)
				if err.lower().startswith("unknown command"):
					logger.error("RedisTimeSeries module missing, metrics collector ending")
					break
			await asyncio.sleep(self._interval)

	def _redis_ts_cmd(self, metric: Metric, cmd: str, value: float, timestamp: int = None, **labels): # pylint: disable=no-self-use
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
		if isinstance(cmd, list):
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
				cmd[2] = timestamp = self._get_timestamp() + 1 # pylint: disable=unused-variable
				cmd = " ".join([ str(x) for x in cmd ])

	#def add_value(self, metric: Metric, value: float, timestamp: int = None, **kwargs):
	async def add_value(self, metric_id: str, value: float, labels: dict = {}, timestamp: int = None): # pylint: disable=unused-variable, dangerous-default-value
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
			if isinstance(server_timing, dict):
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

class StatisticsMiddleware(BaseHTTPMiddleware): # pylint: disable=abstract-method
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

	def yappi(self, scope): # pylint: disable=inconsistent-return-statements
		# https://github.com/sumerc/yappi/blob/master/doc/api.md

		tag = get_yappi_tag()
		if tag == -1:
			return

		#yappi.get_func_stats(filter={"tag": tag}).sort('ttot', sort_order="asc").debug_print()
		max_stats = 500
		if self._log_func_stats:
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------") # pylint: disable=line-too-long
			logger.essential(f"{scope['request_id']} - {scope['client'][0]} - {scope['method']} {scope['path']}")
			logger.essential(f"{'module':<45} | {'function':<60} | {'calls':>5} | {'total time':>10}")
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------") # pylint: disable=line-too-long
			func_stats = yappi.get_func_stats(filter={"tag": tag}).sort("ttot", sort_order="desc")
			for stat_num, stat in enumerate(func_stats):
				module = re.sub(r".*(site-packages|python3\.\d|python-opsi)/", "", stat.module)
				logger.essential(f"{module:<45} | {stat.name:<60} | {stat.ncall:>5} |   {stat.ttot:0.6f}")
				if stat_num >= max_stats:
					break
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------") # pylint: disable=line-too-long

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
		logger.trace("StatisticsMiddleware scope=%s", scope)
		loop = asyncio.get_event_loop()

		if scope["type"] not in ("http", "websocket"):
			await self.app(scope, receive, send)
			return

		start = time.perf_counter()
		contextvar_server_timing.set({})

		# logger.debug("Client Addr: %s", contextvar_client_address.get())
		async def send_wrapper(message: Message) -> None:
			if message["type"] == "http.response.start":
				# Start of response (first message / package)
				loop.create_task(
					get_metrics_collector().add_value(
						"worker:avg_http_request_number",
						1,
						{"node_name": get_node_name(), "worker_num": get_worker_num()}
					)
				)
				loop.create_task(
					get_metrics_collector().add_value(
						"client:sum_http_request",
						1,
						{"client_addr": contextvar_client_address.get()}
					)
				)

				headers = MutableHeaders(scope=message)

				content_length = headers.get("Content-Length", None)
				if content_length is None:
					logger.warning("Header 'Content-Length' missing: %s", message)
				else:
					loop.create_task(
						get_metrics_collector().add_value(
							"worker:avg_http_response_bytes",
							int(content_length),
							{"node_name": get_node_name(), "worker_num": get_worker_num()}
						)
					)

				server_timing = contextvar_server_timing.get() or {}
				if self._profiler_enabled:
					server_timing.update(self.yappi(scope))
				server_timing["request_processing"] = 1000 * (time.perf_counter() - start)
				server_timing = [f"{k};dur={v:.3f}" for k, v in server_timing.items()]
				headers.append("Server-Timing", ','.join(server_timing))

			logger.trace(message)
			await send(message)

			if message["type"] == "http.response.body" and not message.get("more_body"):
				# End of response (last message / package)
				end = time.perf_counter()
				loop.create_task(
					get_metrics_collector().add_value(
						"worker:avg_http_request_duration",
						end - start,
						{"node_name": get_node_name(), "worker_num": get_worker_num()}
					)
				)
				server_timing = contextvar_server_timing.get() or {}
				server_timing["total"] = 1000 * (time.perf_counter() - start)
				logger.info("Server-Timing %s %s: %s", scope["method"], scope["path"],
					', '.join([f"{k}={v:.1f}ms" for k, v in server_timing.items()])
				)

		await self.app(scope, receive, send_wrapper)
