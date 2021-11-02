# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
statistics
"""

import re
import time
import asyncio
from typing import Dict, List
import psutil

import yappi
from yappi import YFuncStats
from aredis.exceptions import ResponseError as ARedisResponseError
from redis import ResponseError as RedisResponseError

from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import (
	contextvar_request_id, contextvar_client_address, contextvar_server_timing
)
from .logging import logger
from .worker import (
	get_metrics_collector as get_worker_metrics_collector,
	get_worker_num
)
from .config import config
from .utils import (
	Singleton, redis_client, aredis_client
)
from .grafana import GrafanaPanelConfig


def get_yappi_tag() -> int:
	return int(contextvar_request_id.get() or -1)


def setup_metric_downsampling() -> None: # pylint: disable=too-many-locals, too-many-branches, too-many-statements
	# Add metrics from jsonrpc to metrics_registry
	from .application import jsonrpc  # pylint: disable=import-outside-toplevel,unused-import

	with redis_client() as client:

		for metric in metrics_registry.get_metrics():
			if not metric.downsampling:
				continue

			iterations = 1
			if metric.subject == "worker":
				iterations = config.workers

			for iteration in range(iterations):
				node_name = config.node_name
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
					client.execute_command(cmd)
				except RedisResponseError as err:
					if str(err) != "TSDB: key already exists":
						raise

				cmd = f"TS.INFO {orig_key}"
				info = client.execute_command(cmd)
				existing_rules = {}
				for idx, val in enumerate(info):
					if isinstance(val, bytes) and "rules" in val.decode("utf8"):
						rules = info[idx+1]
						for rule in rules:
							key = rule[0].decode("utf8")
							#retention = key.split(":")[-1]
							existing_rules[key] = {"time_bucket": rule[1], "aggregation": rule[2].decode("utf8")}

				for rule in metric.downsampling:
					retention, retention_time, aggregation = rule
					time_bucket = get_time_bucket(retention)
					key = f"{orig_key}:{retention}"
					cmd = f"TS.CREATE {key} RETENTION {retention_time} LABELS node_name {node_name} worker_num {worker_num}"
					try:
						client.execute_command(cmd)
					except RedisResponseError as err:
						if str(err) != "TSDB: key already exists":
							raise

					create = True
					if key in existing_rules:
						cur_rule = existing_rules[key]
						if (
							time_bucket == cur_rule.get("time_bucket") and
							aggregation.lower() == cur_rule.get("aggregation").lower()
						):
							create = False
						else:
							cmd = f"TS.DELETERULE {orig_key} {key}"
							client.execute_command(cmd)

					if create:
						cmd = f"TS.CREATERULE {orig_key} {key} AGGREGATION {aggregation} {time_bucket}"
						logger.debug("Redis cmd: %s", cmd)
						client.execute_command(cmd)

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
			zero_if_missing: str = None,
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
		:param zero_if_missing: Behaviour if no values exist in a measuring interval. `one`, `continuous` or None. \
		                        Zero values are sometime helpful because gaps between values get connected \
                                by a straight line in diagrams. But zero values need storage space.
		:type zero_if_missing: str
		:param time_related: If the metric is time related, like requests per second.
		:type time_related: bool
		:param subject: Metric subject (`node`, `worker` or `client`). Should be the first part of the `id` also.
		:type subject: str
		:param subject: A GrafanaPanelConfig object.
		:type subject: GrafanaPanelConfig
		:param downsampling: Downsampling configuration as list of [<time_bucket>, <retention_time>, <aggregation>] pairs.
		:type downsampling: List
		"""
		assert aggregation in ("sum", "avg")
		assert subject in ("node", "worker", "client")
		assert zero_if_missing in (None, "one", "continuous")
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

	def __str__(self):
		return f"<{self.__class__.__name__} id='{self.id}'>"

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

	def get_metrics(self, *subject) -> List[Metric]:
		for metric in self._metrics_by_id.values():
			if not subject or metric.subject in subject:
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
		zero_if_missing=None,
		subject="node",
		grafana_config=GrafanaPanelConfig(title="System load", units=["short"], decimals=2, stack=False),
		downsampling=[["minute", 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"], ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]]
	),
	Metric(
		id="worker:avg_mem_allocated",
		name="Average memory usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=None,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Worker memory usage", units=["decbytes"], decimals=2, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"], ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]]
	),
	Metric(
		id="worker:avg_cpu_percent",
		name="Average CPU usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=None,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Worker CPU usage", units=["percent"], decimals=1, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"], ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]]
	),
	Metric(
		id="worker:avg_thread_number",
		name="Average threads of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=None,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Worker threads", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"], ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]]
	),
	Metric(
		id="worker:avg_filehandle_number",
		name="Average filehandles of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=None,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Worker filehandles", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"], ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]]
	),
	Metric(
		id="worker:sum_http_request_number",
		name="Average HTTP requests of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="sum",
		zero_if_missing="continuous",
		time_related=True,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP requests/s", units=["short"], decimals=0, stack=True),
		downsampling=[["minute", 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"], ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]]
	),
	Metric(
		id="worker:avg_http_response_bytes",
		name="Average HTTP response size of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing="one",
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP response size", units=["decbytes"], stack=True),
		downsampling=[["minute", 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"], ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]]
	),
	Metric(
		id="worker:avg_http_request_duration",
		name="Average duration of HTTP requests processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing="one",
		subject="worker",
		grafana_config=GrafanaPanelConfig(type="heatmap", title="HTTP request duration", units=["s"], decimals=0),
		downsampling=[["minute", 24 * 3600 * 1000, "avg"], ["hour", 60 * 24 * 3600 * 1000, "avg"], ["day", 4 * 365 * 24 * 3600 * 1000, "avg"]]
	),
	Metric(
		id="client:sum_http_request_number",
		name="HTTP requests of Client {client_addr}",
		vars=["client_addr"],
		retention=24 * 3600 * 1000,
		aggregation="sum",
		zero_if_missing="one",
		time_related=True,
		subject="client",
		# Deactivating for now because it slows down grafana a lot in big environments.
		#grafana_config=GrafanaPanelConfig(title="Client HTTP requests/s", units=["short"], decimals=0, stack=False)
	)
)


class MetricsCollector(): #  pylint: disable=too-many-instance-attributes
	_metric_subjects = []

	def __init__(self):
		self._loop = asyncio.get_event_loop()
		self._interval = 5
		self._node_name = config.node_name
		self._values = {}
		self._values_lock = asyncio.Lock()
		self._last_timestamp = 0

	def _get_timestamp(self) -> int: # pylint: disable=no-self-use
		# return unix timestamp in millis
		return int(time.time() * 1000)

	async def _fetch_values(self):
		self._loop.create_task(
			self.add_value("node:avg_load", psutil.getloadavg()[0], {"node_name": self._node_name})
		)

	def _init_vars(self):
		for metric in metrics_registry.get_metrics(*self._metric_subjects):
			if metric.zero_if_missing != "continuous":
				continue

			key_string = []
			for var in metric.vars:
				if hasattr(self, var):
					key_string.append(str(getattr(self, var)))
				elif hasattr(self, f"_{var}"):
					key_string.append(str(getattr(self, f"_{var}")))
				else:
					key_string = None
					break

			if key_string is None:
				continue

			key_string = ":".join(key_string)
			if not metric.id in self._values:
				self._values[metric.id] = {}
			if not key_string in self._values[metric.id]:
				self._values[metric.id][key_string] = {}

	async def main_loop(self): # pylint: disable=too-many-branches
		try:
			self._init_vars()
		except Exception as err: # pylint: disable=broad-except
			logger.error(err, exc_info=True)

		while True:
			cmd = None

			try:
				await self._fetch_values()
				timestamp = self._get_timestamp()
				cmds = []
				async with self._values_lock:
					for metric in metrics_registry.get_metrics(*self._metric_subjects):
						if not metric.id in self._values:
							continue

						for key_string in list(self._values.get(metric.id, {})):
							value = 0
							count = 0
							insert_zero_timestamp = 0
							for tsp in list(self._values[metric.id].get(key_string, {})):
								if self._values[metric.id][key_string][tsp] is None:
									# Marker, insert a zero before adding new values
									insert_zero_timestamp = tsp
									self._values[metric.id][key_string].pop(tsp)
									continue
								if tsp <= timestamp:
									count += 1
									value += self._values[metric.id][key_string].pop(tsp)

							if count == 0:
								if not metric.zero_if_missing:
									continue
								if not insert_zero_timestamp and metric.zero_if_missing == "one":
									del self._values[metric.id][key_string]

							if metric.aggregation == "avg" and count > 0:
								value /= count

							labels = {}
							label_values = key_string.split(":")
							for idx, var in enumerate(metric.vars):
								labels[var] = label_values[idx]

							if insert_zero_timestamp:
								cmds.append(
									self._redis_ts_cmd(metric, "ADD", 0, insert_zero_timestamp, **labels)
								)

							cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
							logger.debug("Redis ts cmd %s", cmd)
							cmds.append(cmd)

				try:
					await self._execute_redis_command(*cmds)
				except ARedisResponseError as err: # pylint: disable=broad-except
					if str(err).lower().startswith("unknown command"):
						logger.error("RedisTimeSeries module missing, metrics collector ending")
						return
					logger.error("%s while executing redis commands: %s", err, cmds, exc_info=True)

			except Exception as err: # pylint: disable=broad-except
				logger.error(err, exc_info=True)
			await asyncio.sleep(self._interval)

	def _redis_ts_cmd(self, metric: Metric, cmd: str, value: float, timestamp: int = None, **labels): # pylint: disable=no-self-use
		timestamp = timestamp or "*"
		l_labels = [list(pair) for pair in labels.items()]

		# ON_DUPLICATE SUM needs Redis Time Series >= 1.4.6
		if cmd == "ADD":
			cmd = [
				"TS.ADD", metric.get_redis_key(**labels), timestamp, value,
				"RETENTION", metric.retention, "ON_DUPLICATE", "SUM", "LABELS"
			] + l_labels
		elif cmd == "INCRBY":
			cmd = [
				"TS.INCRBY", metric.get_redis_key(**labels), value, timestamp,
				"RETENTION", metric.retention, "ON_DUPLICATE", "SUM", "LABELS"
			] + l_labels
		else:
			raise ValueError(f"Invalid command {cmd}")
		return " ".join([ str(x) for x in cmd ])

	@staticmethod
	async def _execute_redis_command(*cmd):
		def str_cmd(cmd_obj):
			if isinstance(cmd_obj, list):
				return " ".join([ str(x) for x in cmd_obj ])
			return cmd_obj

		redis = await aredis_client()
		if len(cmd) == 1:
			return await redis.execute_command(str_cmd(cmd[0]))

		async with await redis.pipeline(transaction=False) as pipe:
			for a_cmd in cmd:
				a_cmd = str_cmd(a_cmd)
				logger.debug("Adding redis command to pipe: %s", a_cmd)
				await pipe.execute_command(a_cmd)
			logger.debug("Executing redis pipe (%d commands)", len(cmd))
			return await pipe.execute()

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
			if not metric_id in self._values:
				self._values[metric_id] = {}
			if not key_string in self._values[metric_id]:
				self._values[metric_id][key_string] = {}
				if metric.zero_if_missing == "one":
					# Insert a zero before new adding new values because
					# gaps in diagrams will be conneced with straight lines.
					# Marking with None
					self._values[metric_id][key_string][timestamp-self._interval*1000] = None
			if not timestamp in self._values[metric_id][key_string]:
				self._values[metric_id][key_string][timestamp] = 0
			self._values[metric_id][key_string][timestamp] += value

class ManagerMetricsCollector(MetricsCollector):
	_metric_subjects = ["node"]

	async def _fetch_values(self):
		self._loop.create_task(
			self.add_value("node:avg_load", psutil.getloadavg()[0], {"node_name": self._node_name})
		)


class WorkerMetricsCollector(MetricsCollector):
	_metric_subjects = ["worker", "client"]

	def __init__(self):
		super().__init__()
		self._worker_num = get_worker_num()
		self._proc = None

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
		self._write_callgrind_file = True
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

		func_stats = yappi.get_func_stats(filter={"tag": tag})
		#func_stats.sort("ttot", sort_order="desc").debug_print()

		if self._write_callgrind_file:
			# Use i.e. kcachegrind to visualize
			func_stats.save(f"/tmp/callgrind.out.opsiconfd-yappi-{tag}", type="callgrind")  # pylint: disable=no-member

		if self._log_func_stats:
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------") # pylint: disable=line-too-long
			logger.essential(f"{scope['request_id']} - {scope['client'][0]} - {scope['method']} {scope['path']}")
			logger.essential(f"{'module':<45} | {'function':<60} | {'calls':>5} | {'total time':>10}")
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------") # pylint: disable=line-too-long
			for stat_num, stat in enumerate(func_stats.sort("ttot", sort_order="desc")):
				module = re.sub(r".*(site-packages|python3\.\d|python-opsi)/", "", stat.module)
				logger.essential(f"{module:<45} | {stat.name:<60} | {stat.ncall:>5} |   {stat.ttot:0.6f}")
				if stat_num >= 500:
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
						{"node_name": config.node_name, "worker_num": get_worker_num()}
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
					if (
						scope["method"] != "OPTIONS" and
						200 <= message.get("status") < 300
					):
						logger.warning("Header 'Content-Length' missing: %s", message)
				else:
					loop.create_task(
						get_worker_metrics_collector().add_value(
							"worker:avg_http_response_bytes",
							int(content_length),
							{"node_name": config.node_name, "worker_num": get_worker_num()}
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
						{"node_name": config.node_name, "worker_num": get_worker_num()}
					)
				)
				server_timing = contextvar_server_timing.get() or {}
				server_timing["total"] = 1000 * (time.perf_counter() - start)
				logger.info("Server-Timing %s %s: %s", scope["method"], scope["path"],
					', '.join([f"{k}={v:.1f}ms" for k, v in server_timing.items()])
				)

		await self.app(scope, receive, send_wrapper)
