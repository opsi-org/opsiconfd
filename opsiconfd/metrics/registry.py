# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
metrics
"""

from __future__ import annotations

import re
from typing import Any, Dict, Generator, List, Type

from opsiconfd.config import config
from opsiconfd.grafana import GrafanaPanelConfig
from opsiconfd.utils import Singleton


class Metric:
	_initialized = False
	vars: list[str] = []

	def __init__(
		self,
		id: str,
		name: str,
		aggregation: str = "avg",
		retention: int = 0,
		zero_if_missing: str | None = None,
		time_related: bool = False,
		grafana_config: GrafanaPanelConfig | None = None,
		downsampling: List | None = None,
	):
		"""
		Metric constructor

		:param id: A unique id for the metric which will be part of the redis key (i.e. "worker:avg_cpu_percent").
		:type id: str
		:param name: The human readable name of the metric (i.e "Average CPU usage of worker {worker_num} on {node_name}").
		:type id: str
		:param retention: Redis retention period (maximum age for samples compared to last event time) in milliseconds.
		:type retention: int
		:param aggregation: Aggregation to use before adding values to the time series database (`sum` or `avg`).
		:type aggregation: str
		:param zero_if_missing:
			Behaviour if no values exist in a measuring interval. `one`, `continuous` or None. \
			Zero values are sometime helpful because gaps between values get connected \
			by a straight line in diagrams. But zero values need storage space.
			`one` should be used with aggregation `avg` and `continuous` with `sum`.
		:type zero_if_missing: str
		:param time_related: If the metric is time related, like requests per second.
		:type time_related: bool
		:param subject: A GrafanaPanelConfig object.
		:type subject: GrafanaPanelConfig
		:param downsampling: Downsampling rules as list of [<ts_key_extension>, <retention_time_in_ms>, <aggregation>] pairs.
		:type downsampling: List
		"""
		if self._initialized:
			return
		self._initialized = True
		assert aggregation in ("sum", "avg")
		assert zero_if_missing in (None, "one", "continuous")
		self.id = id
		self.name = name
		self.aggregation = aggregation
		self.retention = retention
		self.zero_if_missing = zero_if_missing
		self.time_related = time_related
		self.grafana_config = grafana_config
		self.downsampling = downsampling

		self.set_redis_prefix(f"{config.redis_key('stats')}:{id}")

		name_regex = self.name
		for var in self.vars:
			name_regex = name_regex.replace("{" + var + "}", rf"(?P<{var}>\S+)")
		self.name_regex = re.compile(name_regex)

	def __str__(self) -> str:
		return f"<{self.__class__.__name__} id='{self.id}'>"

	def set_redis_prefix(self, prefix: str) -> None:
		self.redis_key = self.redis_key_prefix = prefix
		for var in self.vars:
			self.redis_key += ":{" + var + "}"

	def get_redis_key(self, **kwargs: Any) -> str:
		if not kwargs:
			return self.redis_key_prefix
		return self.redis_key.format(**kwargs)

	def get_name(self, **kwargs: Any) -> str:
		return self.name.format(**kwargs)

	def get_vars_by_redis_key(self, redis_key: str) -> Dict[str, Any]:
		vars = {}
		if self.vars:
			values = redis_key[len(self.redis_key_prefix) + 1 :].split(":")
			vars = {self.vars[i]: value for i, value in enumerate(values)}
		return vars

	def get_name_by_redis_key(self, redis_key: str) -> str:
		vars = self.get_vars_by_redis_key(redis_key)
		return self.get_name(**vars)

	def get_vars_by_name(self, name: str) -> Dict[str, Any]:
		match = self.name_regex.fullmatch(name)
		if not match:
			raise ValueError(f"Name not found {name!r}")
		return match.groupdict(match)


class NodeMetric(Metric):
	vars = ["node_name"]


class WorkerMetric(Metric):
	vars = ["node_name", "worker_num"]


def _get_metrics() -> tuple[Metric, ...]:
	return (
		NodeMetric(
			id="node:avg_load",
			name="Average system load on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing=None,
			grafana_config=GrafanaPanelConfig(title="System load", unit="short", decimals=2, stack=False),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		NodeMetric(
			id="node:sum_network_bits_sent",
			name="Average network bits sent on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="sum",
			zero_if_missing="continuous",
			time_related=True,
			grafana_config=GrafanaPanelConfig(title="Network bits sent/s", unit="bps", decimals=0, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		NodeMetric(
			id="node:sum_network_bits_received",
			name="Average network bits received on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="sum",
			zero_if_missing="continuous",
			time_related=True,
			grafana_config=GrafanaPanelConfig(title="Network bits received/s", unit="bps", decimals=0, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:sum_jsonrpc_requests",
			name="Incoming JSONRPC requests by worker {worker_num} on {node_name}",
			retention=24 * 3600 * 1000,
			aggregation="sum",
			zero_if_missing="continuous",
			time_related=True,
			grafana_config=GrafanaPanelConfig(title="JSONRPC Requests", unit="short", decimals=0, stack=True, yaxis_min=0),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:sum_jsonrpc_number",
			name="Average RPCs processed by worker {worker_num} on {node_name}",
			retention=24 * 3600 * 1000,
			aggregation="sum",
			zero_if_missing="continuous",
			time_related=True,
			grafana_config=GrafanaPanelConfig(title="JSONRPCs/s", unit="short", decimals=0, stack=True, yaxis_min=0),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_jsonrpc_duration",
			name="Average duration of RPCs processed by worker {worker_num} on {node_name}",
			retention=24 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing="one",
			grafana_config=GrafanaPanelConfig(type="heatmap", title="JSONRPC duration", unit="s", decimals=0),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_mem_allocated",
			name="Average memory usage of worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing=None,
			grafana_config=GrafanaPanelConfig(title="Worker memory usage", unit="decbytes", decimals=2, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_cpu_percent",
			name="Average CPU usage of worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing=None,
			grafana_config=GrafanaPanelConfig(title="Worker CPU usage", unit="percent", decimals=1, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_thread_number",
			name="Average threads of worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing=None,
			grafana_config=GrafanaPanelConfig(title="Worker threads", unit="short", decimals=0, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_filehandle_number",
			name="Average filehandles of worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing=None,
			grafana_config=GrafanaPanelConfig(title="Worker filehandles", unit="short", decimals=0, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_connection_number",
			name="Average connections of worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing=None,
			grafana_config=GrafanaPanelConfig(title="Worker connections", unit="short", decimals=0, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:sum_http_request_number",
			name="Average HTTP requests of worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="sum",
			zero_if_missing="continuous",
			time_related=True,
			grafana_config=GrafanaPanelConfig(title="HTTP requests/s", unit="short", decimals=0, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_http_request_bytes",
			name="Average HTTP request size of worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing="one",
			grafana_config=GrafanaPanelConfig(title="HTTP request size", unit="decbytes", stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_http_response_bytes",
			name="Average HTTP response size of worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing="one",
			grafana_config=GrafanaPanelConfig(title="HTTP response size", unit="decbytes", stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:avg_http_request_duration",
			name="Average duration of HTTP requests processed by worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="avg",
			zero_if_missing="one",
			grafana_config=GrafanaPanelConfig(type="heatmap", title="HTTP request duration", unit="s", decimals=0),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:sum_messagebus_messages_sent",
			name="Average messagebus messages sent by worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="sum",
			zero_if_missing="continuous",
			time_related=True,
			grafana_config=GrafanaPanelConfig(title="Messagebus messages sent/s", unit="short", decimals=0, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
		WorkerMetric(
			id="worker:sum_messagebus_messages_received",
			name="Average messagebus messages received by worker {worker_num} on {node_name}",
			retention=2 * 3600 * 1000,
			aggregation="sum",
			zero_if_missing="continuous",
			time_related=True,
			grafana_config=GrafanaPanelConfig(title="Messagebus messages received/s", unit="short", decimals=0, stack=True),
			downsampling=[
				["minute", 24 * 3600 * 1000, "avg"],
				["hour", 60 * 24 * 3600 * 1000, "avg"],
				["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
			],
		),
	)


class MetricsRegistry(metaclass=Singleton):
	def __init__(self) -> None:
		self._metrics_by_id: Dict[str, Metric] = {}
		self.register(*_get_metrics())

	def register(self, *metric: Metric) -> None:
		for met in metric:
			self._metrics_by_id[met.id] = met

	def get_metric_ids(self) -> list[str]:
		return list(self._metrics_by_id)

	def get_metrics(self, *types: Type[Metric]) -> Generator[Metric, None, None]:
		types = tuple(types)
		for metric in self._metrics_by_id.values():
			if not types or isinstance(metric, types):
				yield metric

	def get_metric_by_id(self, id: str) -> Metric:
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
