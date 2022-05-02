# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
metrics
"""

import asyncio
import re
import time
from typing import TYPE_CHECKING, Generator, List, Tuple

import psutil
from aioredis import ResponseError as AioRedisResponseError

from . import contextvar_server_timing
from .config import config
from .grafana import GrafanaPanelConfig
from .logging import logger
from .utils import Singleton, async_redis_client

if TYPE_CHECKING:
	# Prevent circular import error
	from .worker import Worker


class Metric:  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments, redefined-builtin, dangerous-default-value
		self,
		id: str,  # pylint: disable=invalid-name
		name: str,
		vars: List[str] = [],
		aggregation: str = "avg",
		retention: int = 0,
		zero_if_missing: str = None,
		time_related: bool = False,
		subject: str = "worker",
		server_timing_header_factor: int = None,
		grafana_config: GrafanaPanelConfig = None,
		downsampling: List = None,
	):
		"""
		Metric constructor

		:param id: A unique id for the metric which will be part of the redis key (i.e. "worker:avg_cpu_percent").
		:type id: str
		:param name: The human readable name of the metric (i.e "Average CPU usage of worker {worker_num} on {node_name}").
		:type id: str
		:param vars:
			Variables used for redis key and labels (i.e. ["node_name", "worker_num"]). \
			Values for these vars has to pe passed to param "labels" as dict when calling MetricsCollector.add_value().
		:type vars: List[str]
		:param retention: Redis retention period (maximum age for samples compared to last event time) in milliseconds.
		:type retention: int
		:param aggregation: Aggregation to use before adding values to the time series database (`sum` or `avg`).
		:type aggregation: str
		:param zero_if_missing:
			Behaviour if no values exist in a measuring interval. `one`, `continuous` or None. \
			Zero values are sometime helpful because gaps between values get connected \
			by a straight line in diagrams. But zero values need storage space.
		:type zero_if_missing: str
		:param time_related: If the metric is time related, like requests per second.
		:type time_related: bool
		:param subject: Metric subject (`node`, `worker` or `client`). Should be the first part of the `id` also.
		:type subject: str
		:param subject: A GrafanaPanelConfig object.
		:type subject: GrafanaPanelConfig
		:param downsampling: Downsampling rules as list of [<ts_key_extension>, <retention_time_in_ms>, <aggregation>] pairs.
		:type downsampling: List
		"""
		assert aggregation in ("sum", "avg")
		assert subject in ("node", "worker", "client")
		assert zero_if_missing in (None, "one", "continuous")
		self.id = id  # pylint: disable=invalid-name
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
			name_regex = name_regex.replace("{" + var + "}", rf"(?P<{var}>\S+)")  # pylint: disable=anomalous-backslash-in-string
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
		vars = {}  # pylint: disable=redefined-builtin
		if self.vars:
			values = redis_key[len(self.redis_key_prefix) + 1 :].split(":")
			vars = {self.vars[i]: value for i, value in enumerate(values)}
		return vars

	def get_name_by_redis_key(self, redis_key):
		vars = self.get_vars_by_redis_key(redis_key)  # pylint: disable=redefined-builtin
		return self.get_name(**vars)

	def get_vars_by_name(self, name):
		return self.name_regex.fullmatch(name).groupdict()


class MetricsRegistry(metaclass=Singleton):
	def __init__(self):
		self._metrics_by_id = {}

	def register(self, *metric):
		for m in metric:  # pylint: disable=invalid-name
			self._metrics_by_id[m.id] = m

	def get_metric_ids(self):
		return list(self._metrics_by_id)

	def get_metrics(self, *subject) -> Generator[Metric, None, None]:
		for metric in self._metrics_by_id.values():
			if not subject or metric.subject in subject:
				yield metric

	def get_metric_by_id(self, id):  # pylint: disable=redefined-builtin, invalid-name
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
			if redis_key == metric.redis_key_prefix or redis_key.startswith(metric.redis_key_prefix + ":"):
				return metric
		raise ValueError(f"Metric with redis key '{redis_key}' not found")


metrics_registry = MetricsRegistry()


class MetricsCollector:  # pylint: disable=too-many-instance-attributes
	_metric_subjects: Tuple = ()

	def __init__(self):
		self._interval = 5
		self._node_name = config.node_name
		self._values = {}
		self._values_lock = asyncio.Lock()
		self._last_timestamp = 0
		self._should_stop = False

	def stop(self):
		self._should_stop = True

	def _get_timestamp(self) -> int:  # pylint: disable=no-self-use
		# return unix timestamp in millis
		return int(time.time() * 1000)

	async def _fetch_values(self):
		asyncio.get_event_loop().create_task(self.add_value("node:avg_load", psutil.getloadavg()[0], {"node_name": self._node_name}))

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
			if metric.id not in self._values:
				self._values[metric.id] = {}
			if key_string not in self._values[metric.id]:
				self._values[metric.id][key_string] = {}

	async def main_loop(self):  # pylint: disable=too-many-branches,too-many-locals
		try:
			self._init_vars()
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

		while True:
			cmd = None

			try:  # pylint: disable=loop-try-except-usage
				await self._fetch_values()
				timestamp = self._get_timestamp()
				cmds = []
				async with self._values_lock:
					for metric in metrics_registry.get_metrics(*self._metric_subjects):
						if metric.id not in self._values:
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
								cmds.append(self._redis_ts_cmd(metric, "ADD", 0, insert_zero_timestamp, **labels))

							cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
							logger.debug("Redis ts cmd %s", cmd)
							cmds.append(cmd)

				try:
					await self._execute_redis_command(*cmds)
				except AioRedisResponseError as err:  # pylint: disable=broad-except
					if str(err).lower().startswith("unknown command"):
						logger.error("RedisTimeSeries module missing, metrics collector ending")
						return
					logger.error("%s while executing redis commands: %s", err, cmds, exc_info=True)

			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
			for _ in range(self._interval):
				if self._should_stop:
					return
				await asyncio.sleep(1)

	@staticmethod
	def _redis_ts_cmd(metric: Metric, cmd: str, value: float, timestamp: int = None, **labels):
		timestamp_str: str = str(timestamp or "*")
		l_labels = [list(pair) for pair in labels.items()]

		# ON_DUPLICATE SUM needs Redis Time Series >= 1.4.6
		if cmd == "ADD":
			ts_cmd = [
				"TS.ADD",
				metric.get_redis_key(**labels),
				timestamp_str,
				value,
				"RETENTION",
				metric.retention,
				"ON_DUPLICATE",
				"SUM",
				"LABELS",
			] + l_labels
		elif cmd == "INCRBY":
			ts_cmd = [
				"TS.INCRBY",
				metric.get_redis_key(**labels),
				value,
				timestamp_str,
				"RETENTION",
				metric.retention,
				"ON_DUPLICATE",
				"SUM",
				"LABELS",
			] + l_labels
		else:
			raise ValueError(f"Invalid command {cmd}")
		return " ".join([str(x) for x in ts_cmd])

	@staticmethod
	async def _execute_redis_command(*cmd):
		def str_cmd(cmd_obj):
			if isinstance(cmd_obj, list):
				return " ".join([str(x) for x in cmd_obj])
			return cmd_obj

		redis = await async_redis_client()
		if len(cmd) == 1:
			return await redis.execute_command(str_cmd(cmd[0]))

		async with redis.pipeline(transaction=False) as pipe:
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
				server_timing[metric_id.split(":")[-1]] = value * metric.server_timing_header_factor
				contextvar_server_timing.set(server_timing)
		if not timestamp:
			timestamp = self._get_timestamp()
		async with self._values_lock:
			if metric_id not in self._values:
				self._values[metric_id] = {}
			if key_string not in self._values[metric_id]:
				self._values[metric_id][key_string] = {}
				if metric.zero_if_missing == "one":
					# Insert a zero before new adding new values because
					# gaps in diagrams will be conneced with straight lines.
					# Marking with None
					self._values[metric_id][key_string][timestamp - self._interval * 1000] = None
			if timestamp not in self._values[metric_id][key_string]:
				self._values[metric_id][key_string][timestamp] = 0
			self._values[metric_id][key_string][timestamp] += value


class ManagerMetricsCollector(MetricsCollector):
	_metric_subjects = ("node",)

	async def _fetch_values(self):
		asyncio.get_event_loop().create_task(self.add_value("node:avg_load", psutil.getloadavg()[0], {"node_name": self._node_name}))


class WorkerMetricsCollector(MetricsCollector):
	_metric_subjects = ("worker", "client")

	def __init__(self, worker: "Worker") -> None:
		super().__init__()
		self.worker = worker
		self._proc = None

	@property
	def worker_num(self) -> int:
		return self.worker.worker_num

	async def _fetch_values(self):
		if not self._proc:
			self._proc = psutil.Process()

		for metric_id, value in (
			("worker:avg_mem_allocated", self._proc.memory_info().rss),
			("worker:avg_cpu_percent", self._proc.cpu_percent()),
			("worker:avg_thread_number", self._proc.num_threads()),
			("worker:avg_filehandle_number", self._proc.num_fds()),
		):
			# Do not add 0-values
			if value:
				asyncio.get_event_loop().create_task(  # pylint: disable=dotted-import-in-loop
					self.add_value(metric_id, value, {"node_name": self._node_name, "worker_num": self.worker_num})
				)
