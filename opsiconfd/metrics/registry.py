# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
metrics
"""

from __future__ import annotations

import re
from typing import Any, Dict, Generator, List

from ..grafana import GrafanaPanelConfig
from ..utils import Singleton


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

	def __str__(self) -> str:
		return f"<{self.__class__.__name__} id='{self.id}'>"

	def get_redis_key(self, **kwargs: Any) -> str:
		if not kwargs:
			return self.redis_key_prefix
		return self.redis_key.format(**kwargs)

	def get_name(self, **kwargs: Any) -> str:
		return self.name.format(**kwargs)

	def get_vars_by_redis_key(self, redis_key: str) -> Dict[str, Any]:
		vars = {}  # pylint: disable=redefined-builtin
		if self.vars:
			values = redis_key[len(self.redis_key_prefix) + 1 :].split(":")
			vars = {self.vars[i]: value for i, value in enumerate(values)}
		return vars

	def get_name_by_redis_key(self, redis_key: str) -> str:
		vars = self.get_vars_by_redis_key(redis_key)  # pylint: disable=redefined-builtin
		return self.get_name(**vars)

	def get_vars_by_name(self, name: str) -> Dict[str, Any]:
		match = self.name_regex.fullmatch(name)
		if not match:
			raise ValueError(f"Name not found {name!r}")
		return match.groupdict(match)


METRICS = (
	Metric(
		id="worker:sum_jsonrpc_number",
		name="Average RPCs processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		aggregation="sum",
		zero_if_missing="continuous",
		time_related=True,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="JSONRPCs/s", units=["short"], decimals=0, stack=True, yaxis_min=0),
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
	),
	Metric(
		id="worker:avg_jsonrpc_duration",
		name="Average duration of RPCs processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing="one",
		subject="worker",
		server_timing_header_factor=1000,
		grafana_config=GrafanaPanelConfig(type="heatmap", title="JSONRPC duration", units=["s"], decimals=0),
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
	),
	Metric(
		id="node:avg_load",
		name="Average system load on {node_name}",
		vars=["node_name"],
		retention=2 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing=None,
		subject="node",
		grafana_config=GrafanaPanelConfig(title="System load", units=["short"], decimals=2, stack=False),
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		# grafana_config=GrafanaPanelConfig(title="Client HTTP requests/s", units=["short"], decimals=0, stack=False)
	)
)


class MetricsRegistry(metaclass=Singleton):
	def __init__(self) -> None:
		self._metrics_by_id: Dict[str, Metric] = {}
		self.register(*METRICS)

	def register(self, *metric: Metric) -> None:
		for met in metric:
			self._metrics_by_id[met.id] = met

	def get_metric_ids(self) -> List[str]:
		return list(self._metrics_by_id)

	def get_metrics(self, *subject: str) -> Generator[Metric, None, None]:
		for metric in self._metrics_by_id.values():
			if not subject or metric.subject in subject:
				yield metric

	def get_metric_by_id(self, id: str) -> Metric:  # pylint: disable=redefined-builtin, invalid-name
		if id in self._metrics_by_id:
			return self._metrics_by_id[id]
		raise ValueError(f"Metric with id '{id}' not found")

	def get_metric_by_name(self, name: str) -> Metric:
		for metric in self._metrics_by_id.values():
			match = metric.name_regex.fullmatch(name)
			if match:
				return metric
		raise ValueError(f"Metric with name '{name}' not found")

	def get_metric_by_redis_key(self, redis_key: str) -> Metric:
		for metric in self._metrics_by_id.values():
			if redis_key == metric.redis_key_prefix or redis_key.startswith(metric.redis_key_prefix + ":"):
				return metric
		raise ValueError(f"Metric with redis key '{redis_key}' not found")
