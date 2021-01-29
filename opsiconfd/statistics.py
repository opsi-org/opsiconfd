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
	contextvar_request_id, contextvar_client_address, contextvar_server_timing
)
from .worker import get_redis_client as get_worker_redis_client
from .worker import get_metrics_collector as get_worker_metrics_collector

from .arbiter import get_redis_client as get_arbiter_redis_client

from .config import config
from .utils import (
	Singleton, get_node_name, get_worker_num, get_redis_connection, get_aredis_connection
)
from .grafana import GrafanaPanelConfig

def get_yappi_tag() -> int:
	return int(contextvar_request_id.get() or -1)


def setup_metric_downsampling() -> None: # pylint: disable=too-many-locals, too-many-branches, too-many-statements

	redis_client = get_redis_connection(config.redis_internal_url)

	for metric in metrics_registry.get_metrics():
		if not metric.downsampling:
			continue

		iterations = 1
		if metric.subject == "worker":
			iterations = config.workers

		for iteration in range(iterations):
			node_name = get_node_name()
			worker_num = None
			if metric.subject == "worker":
				worker_num = iteration + 1

			logger.debug("Iteration=%s, node_name=%s, worker_num=%s", iteration, node_name, worker_num)

			orig_key = None
			cmd = None
			if metric.subject == "worker":
				orig_key = metric.redis_key.format(node_name=node_name, worker_num=worker_num)
				cmd = f"TS.CREATE {orig_key} RETENTION {metric.retention} LABELS node_name {node_name} worker_num {worker_num}"
			elif metric.subject == "node":
				orig_key = metric.redis_key.format(node_name=node_name)
				cmd = f"TS.CREATE {orig_key} RETENTION {metric.retention} LABELS node_name {node_name}"
			else:
				orig_key = metric.redis_key
				cmd = f"TS.CREATE {orig_key} RETENTION {metric.retention}"

			logger.debug("redis command: %s", cmd)
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
				key = f"{orig_key}:{rule[0]}"
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


TIME_BUCKETS = {
	"second": 1000,
	"minute": 60 * 1000,
	"hour": 3600 * 1000,
	"day": 24 * 3600 * 1000,
	"week": 7 * 24 * 3600 * 1000,
	"month": 30 * 24 * 3600 * 1000,
	"year": 365 * 24 * 3600 * 1000
}

def get_time_bucket(interval: str) -> int:
	time_bucket = TIME_BUCKETS.get(interval)
	if time_bucket is None:
		raise ValueError(f"Invalid interval: {interval}")
	return time_bucket


def get_time_bucket_name(time: int) -> str: # pylint: disable=redefined-outer-name
	time_bucket_name = None
	for name, t in TIME_BUCKETS.items(): # pylint: disable=invalid-name
		if time >= t:
			time_bucket_name = name
	return time_bucket_name

class Metric: # pylint: disable=too-many-instance-attributes
	def __init__( # pylint: disable=too-many-arguments, redefined-builtin, dangerous-default-value
			self,
			id: str,
			name: str,
			vars: List[str] = [],
			aggregation: str = "avg",
			retention: int = 0,
			zero_if_missing: bool = True,
			time_related: bool = False,
			subject: str = "worker",
			server_timing_header_factor: int = None,
			grafana_config: GrafanaPanelConfig = None,
			downsampling: List = None
	):
		"""
		Metric constructor

		:param id: A unique id for the metric which will be part of the redis key (i.e. "worker:avg_cpu_percent").
		:type id: str
		:param name: The human readable name of the metric (i.e "Average CPU usage of worker {worker_num} on {node_name}").
		:type id: str
		:param vars: Variables used for redis key and labels (i.e. ["node_name", "worker_num"]). \
		             Values for these vars has to pe passed to param "labels" as dict when calling MetricsCollector.add_value().
		:type vars: List[str]
		:param retention: Redis retention time in milliseconds.
		:type retention: int
		:param aggregation: Aggregation to use before adding values to the time series database (`sum` or `avg`).
		:type aggregation: str
		:param zero_if_missing: If a value of 0 is inserted if no values exist in a measuring interval.
		:type zero_if_missing: bool
		:param time_related: If the metric is time related, like requests per second.
		:type time_related: bool
		:param subject: Metric subject (`node`, `worker` or `client`). Should be the first part of the `id` also.
		:type subject: str
		:param subject: A GrafanaPanelConfig object.
		:type subject: GrafanaPanelConfig
		:param downsampling: Downsampling configuration as list of [<time_bucket>, <retention_time>] pairs.
		:type downsampling: List
		"""
		assert aggregation in ("sum", "avg")
		assert subject in ("node", "worker", "client")
		self.id = id # pylint: disable=invalid-name
		self.name = name
		self.vars = vars
		self.aggregation = aggregation
		self.retention = retention
		self.zero_if_missing = zero_if_missing
		self.time_related = time_related
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
		id="node:avg_load",
		name="Average system load on {node_name}",
		vars=["node_name"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=False,
		subject="node",
		grafana_config=GrafanaPanelConfig(title="System load", units=["short"], decimals=2, stack=False),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_mem_allocated",
		name="Average memory usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=False,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Worker memory usage", units=["decbytes"], stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_cpu_percent",
		name="Average CPU usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=False,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Worker CPU usage", units=["percent"], decimals=1, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_thread_number",
		name="Average threads of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=False,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Worker threads", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_filehandle_number",
		name="Average filehandles of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=False,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Worker filehandles", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:sum_http_request_number",
		name="Average HTTP requests of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="sum",
		zero_if_missing=True,
		time_related=True,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP requests/s", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_http_response_bytes",
		name="Average HTTP response size of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=False,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP response size", units=["decbytes"], stack=True),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_http_request_duration",
		name="Average duration of HTTP requests processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=False,
		subject="worker",
		grafana_config=GrafanaPanelConfig(type="heatmap", title="HTTP request duration", units=["s"], decimals=0),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="client:sum_http_request_number",
		name="HTTP requests of Client {client_addr}",
		vars=["client_addr"],
		retention=24 * 3600 * 1000,
		aggregation="sum",
		zero_if_missing=False,
		time_related=True,
		subject="client",
		grafana_config=GrafanaPanelConfig(title="Client HTTP requests/s", units=["short"], decimals=0, stack=False)
	)
)


class MetricsCollector(): #  pylint: disable=too-many-instance-attributes
	def __init__(self):
		self._loop = asyncio.get_event_loop()
		self._interval = 5
		self._node_name = get_node_name()
		self._values = {}
		self._values_lock = asyncio.Lock()
		self._last_timestamp = 0

	def _get_timestamp(self) -> int: # pylint: disable=no-self-use
		# return unix timestamp in millis
		# milliseconds since Jan 01 1970. (UTC)
		return int(time.time() * 1000)
		#return int(round(datetime.datetime.utcnow().timestamp())*1000)

	async def _fetch_values(self):
		self._loop.create_task(
			self.add_value("node:avg_load", psutil.getloadavg()[0], {"node_name": self._node_name})
		)

	async def main_loop(self):
		while True:
			cmd = None

			try:
				await self._fetch_values()
				timestamp = self._get_timestamp()

				for metric in metrics_registry.get_metrics():
					if not metric.id in self._values:
						continue

					async with self._values_lock:
						for key_string in self._values.get(metric.id, {}):
							value = 0
							count = 0
							for tsp in list(self._values[metric.id].get(key_string, {})):
								if tsp <= timestamp:
									count += 1
									value += self._values[metric.id][key_string].pop(tsp)

							if count == 0 and not metric.zero_if_missing:
								continue

							if metric.aggregation == "avg" and count > 0:
								value /= count

							labels = {}
							label_values = key_string.split(":")
							for idx, var in enumerate(metric.vars):
								labels[var] = label_values[idx]

							cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
							logger.debug("Redis ts cmd %s", cmd)

							try:
								await self._execute_redis_command(cmd)
							except Exception as err: # pylint: disable=broad-except
								if str(err).lower().startswith("unknown command"):
									logger.error("RedisTimeSeries module missing, metrics collector ending")
									return
								logger.error("%s while executing redis command: %s", err, cmd, exc_info=True)

			except Exception as err: # pylint: disable=broad-except
				logger.error(err, exc_info=True)
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

	async def _get_redis_client(self):
		raise NotImplementedError("Not implemented")

	async def _execute_redis_command(self, cmd, max_tries=2):
		if isinstance(cmd, list):
			cmd = " ".join([ str(x) for x in cmd ])
		logger.debug("Executing redis command: %s", cmd)
		for trynum in range(1, max_tries + 1):
			try:
				redis = await self._get_redis_client()
				return await redis.execute_command(cmd)
			except ResponseError:
				if trynum >= max_tries:
					raise
				# TODO: Remove or refactor, timestamp is not always cmd[2]
				cmd = cmd.split(" ")
				cmd[2] = timestamp = self._get_timestamp() + 1 # pylint: disable=unused-variable
				cmd = " ".join([ str(x) for x in cmd ])

	async def add_value(self, metric_id: str, value: float, labels: dict = None, timestamp: int = None):
		if labels is None:
			labels = {}
		metric = metrics_registry.get_metric_by_id(metric_id)
		logger.debug("add_value metric_id: %s, labels: %s ", metric_id, labels)
		key_string = ""
		for var in metric.vars:
			if not key_string:
				key_string = labels[var]
			else:
				key_string = f"{key_string}:{labels[var]}"

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

class ArbiterMetricsCollector(MetricsCollector):
	async def _fetch_values(self):
		self._loop.create_task(
			self.add_value("node:avg_load", psutil.getloadavg()[0], {"node_name": self._node_name})
		)

	async def _get_redis_client(self):
		return await get_arbiter_redis_client()

class WorkerMetricsCollector(MetricsCollector):
	def __init__(self):
		super().__init__()
		self._worker_num = get_worker_num()
		self._proc = None

	async def _get_redis_client(self):
		return await get_worker_redis_client()

	async def _fetch_values(self):
		if not self._proc:
			self._proc = psutil.Process()

		for metric_id, value in (
			("worker:avg_mem_allocated", self._proc.memory_info().rss),
			("worker:avg_cpu_percent", self._proc.cpu_percent()),
			("worker:avg_thread_number", self._proc.num_threads()),
			("worker:avg_filehandle_number", self._proc.num_fds())
		):
			# Do not add 0-values
			if value:
				self._loop.create_task(
					self.add_value(metric_id, value, {"node_name": self._node_name, "worker_num": self._worker_num})
				)


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
					get_worker_metrics_collector().add_value(
						"worker:sum_http_request_number",
						1,
						{"node_name": get_node_name(), "worker_num": get_worker_num()}
					)
				)
				loop.create_task(
					get_worker_metrics_collector().add_value(
						"client:sum_http_request_number",
						1,
						{"client_addr": contextvar_client_address.get()}
					)
				)

				headers = MutableHeaders(scope=message)

				content_length = headers.get("Content-Length", None)
				if content_length is None:
					if message.get("status") < 300 or message.get("status") >= 400:
						logger.warning("Header 'Content-Length' missing: %s", message)
				else:
					loop.create_task(
						get_worker_metrics_collector().add_value(
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
					get_worker_metrics_collector().add_value(
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
