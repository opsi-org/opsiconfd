# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
statistics
"""

import asyncio
import copy
import re
import time
from typing import Any, Dict, List

from fastapi import FastAPI
from redis import ResponseError as RedisResponseError
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import Message, Receive, Scope, Send

from . import contextvar_client_address, contextvar_request_id, contextvar_server_timing
from .config import config
from .logging import logger
from .metrics import Metric, metrics_registry
from .utils import ip_address_to_redis_key, redis_client
from .worker import Worker

GRAFANA_DASHBOARD_UID = "opsiconfd_main"

GRAFANA_DATASOURCE_TEMPLATE = {
	"orgId": 1,
	"name": "opsiconfd",
	"type": "grafana-simple-json-datasource",
	"typeLogoUrl": "public/plugins/grafana-simple-json-datasource/img/simpleJson_logo.svg",
	"access": "proxy",
	"url": None,
	"password": "",
	"user": "",
	"database": "",
	"basicAuth": True,
	"isDefault": False,
	"jsonData": {"tlsSkipVerify": True},
	"readOnly": False,
}

GRAFANA_DASHBOARD_TEMPLATE: Dict[str, Any] = {
	"id": None,
	"uid": GRAFANA_DASHBOARD_UID,
	"annotations": {
		"list": [
			{
				"builtIn": 1,
				"datasource": "-- Grafana --",
				"enable": True,
				"hide": True,
				"iconColor": "rgba(0, 211, 255, 1)",
				"name": "Annotations & Alerts",
				"type": "dashboard",
			}
		]
	},
	"timezone": "browser",  # "utc", "browser" or "" (default)
	"title": "opsiconfd main dashboard",
	"editable": True,
	"gnetId": None,
	"graphTooltip": 0,
	"links": [],
	"panels": [],
	"refresh": "1m",
	"schemaVersion": 22,
	"version": 12,
	"style": "dark",
	"tags": [],
	"templating": {"list": []},
	"time": {"from": "now-5m", "to": "now"},
	"timepicker": {"refresh_intervals": ["1s", "5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"]},
	"variables": {"list": []},
}

GRAFANA_GRAPH_PANEL_TEMPLATE = {
	"aliasColors": {},
	"bars": False,
	"dashLength": 10,
	"dashes": False,
	"datasource": "opsiconfd",
	"decimals": 0,
	"description": "",
	"fill": 1,
	"fillGradient": 0,
	"gridPos": {"h": 12, "w": 8, "x": 0, "y": 0},
	"hiddenSeries": False,
	"id": None,
	"legend": {
		"alignAsTable": True,
		"avg": True,
		"current": True,
		"hideEmpty": True,
		"hideZero": False,
		"max": True,
		"min": True,
		"show": True,
		"total": False,
		"values": True,
	},
	"lines": True,
	"linewidth": 1,
	"nullPointMode": "null",
	"options": {"dataLinks": []},
	"percentage": False,
	"pointradius": 2,
	"points": False,
	"renderer": "flot",
	"seriesOverrides": [],
	"spaceLength": 10,
	"stack": True,
	"steppedLine": False,
	"targets": [],
	"thresholds": [],
	"timeFrom": None,
	"timeRegions": [],
	"timeShift": None,
	"title": "",
	"tooltip": {"shared": True, "sort": 0, "value_type": "individual"},
	"type": "graph",
	"xaxis": {"buckets": None, "mode": "time", "name": None, "show": True, "values": []},
	"yaxes": [
		{"format": "short", "label": None, "logBase": 1, "max": None, "min": None, "show": True},
		{"format": "short", "label": None, "logBase": 1, "max": None, "min": None, "show": True},
	],
	"yaxis": {"align": False, "alignLevel": None},
}

GRAFANA_HEATMAP_PANEL_TEMPLATE = {
	"datasource": "opsiconfd",
	"description": "",
	"gridPos": {"h": 12, "w": 8, "x": 0, "y": 0},
	"id": None,
	"targets": [],
	"timeFrom": None,
	"timeShift": None,
	"title": "Duration of remote procedure calls",
	"type": "heatmap",
	"heatmap": {},
	"cards": {"cardPadding": None, "cardRound": None},
	"color": {
		"mode": "opacity",
		"cardColor": "#73BF69",
		"colorScale": "sqrt",
		"exponent": 0.5,
		# "colorScheme": "interpolateSpectral",
		"min": None,
	},
	"legend": {"show": False},
	"dataFormat": "timeseries",
	"yBucketBound": "auto",
	"reverseYBuckets": False,
	"xAxis": {"show": True},
	"yAxis": {"show": True, "format": "s", "decimals": 2, "logBase": 2, "splitFactor": None, "min": "0", "max": None},
	"xBucketSize": None,
	"xBucketNumber": None,
	"yBucketSize": None,
	"yBucketNumber": None,
	"tooltip": {"show": False, "showHistogram": False},
	"highlightCards": True,
	"hideZeroBuckets": False,
	"tooltipDecimals": 0,
}


class GrafanaPanelConfig:  # pylint: disable=too-few-public-methods
	def __init__(  # pylint: disable=too-many-arguments
		self,
		type: str = "graph",  # pylint: disable=redefined-builtin
		title: str = "",
		units: List[str] | None = None,
		decimals: int = 0,
		stack: bool = False,
		yaxis_min: int | str = "auto",
	) -> None:
		self.type = type
		self.title = title
		self.units = units or ["short", "short"]
		self.decimals = decimals
		self.stack = stack
		self._template = {}
		self.yaxis_min = yaxis_min
		if self.type == "graph":
			self._template = GRAFANA_GRAPH_PANEL_TEMPLATE
		elif self.type == "heatmap":
			self._template = GRAFANA_HEATMAP_PANEL_TEMPLATE  # type: ignore[assignment]

	def get_panel(self, panel_id: int = 1, pos_x: int = 0, pos_y: int = 0) -> Dict[str, Any]:
		panel = copy.deepcopy(self._template)
		panel["id"] = panel_id
		panel["gridPos"]["x"] = pos_x  # type: ignore[index]
		panel["gridPos"]["y"] = pos_y  # type: ignore[index]
		panel["title"] = self.title
		if self.type == "graph":
			panel["stack"] = self.stack
			panel["decimals"] = self.decimals
			for i, unit in enumerate(self.units):
				panel["yaxes"][i]["format"] = unit  # type: ignore[index]  # pylint: disable=loop-invariant-statement
		elif self.type == "heatmap":
			panel["yAxis"]["format"] = self.units[0]  # type: ignore[index]
			panel["tooltipDecimals"] = self.decimals
		if self.yaxis_min != "auto":
			for axis in panel["yaxes"]:  # type: ignore[attr-defined]
				axis["min"] = self.yaxis_min
		return panel


def setup_metric_downsampling() -> None:  # pylint: disable=too-many-locals, too-many-branches, too-many-statements
	# Add metrics from jsonrpc to metrics_registry
	from .application import (  # pylint: disable=import-outside-toplevel,unused-import
		jsonrpc,
	)

	with redis_client() as client:
		for metric in metrics_registry.get_metrics():
			subject_is_worker = metric.subject == "worker"
			if not metric.downsampling:
				continue

			iterations = 1
			if subject_is_worker:
				iterations = config.workers

			for iteration in range(iterations):
				node_name = config.node_name
				worker_num = None
				if subject_is_worker:
					worker_num = iteration + 1

				logger.debug("Iteration=%s, node_name=%s, worker_num=%s", iteration, node_name, worker_num)

				orig_key = None
				cmd = None
				if subject_is_worker:
					orig_key = metric.redis_key.format(node_name=node_name, worker_num=worker_num)
					cmd = f"TS.CREATE {orig_key} RETENTION {metric.retention} LABELS node_name {node_name} worker_num {worker_num}"
				elif metric.subject == "node":  # pylint: disable=loop-invariant-statement
					orig_key = metric.redis_key.format(node_name=node_name)
					cmd = f"TS.CREATE {orig_key} RETENTION {metric.retention} LABELS node_name {node_name}"
				else:
					orig_key = metric.redis_key
					cmd = f"TS.CREATE {orig_key} RETENTION {metric.retention}"

				logger.debug("redis command: %s", cmd)
				try:  # pylint: disable=loop-try-except-usage
					client.execute_command(cmd)
				except RedisResponseError as err:  # pylint: disable=loop-invariant-statement
					if str(err) != "TSDB: key already exists":  # pylint: disable=loop-invariant-statement
						raise

				cmd = f"TS.INFO {orig_key}"
				info = client.execute_command(cmd)
				existing_rules: Dict[str, Dict[str, str]] = {}  # pylint: disable=loop-invariant-statement
				for idx, val in enumerate(info):
					if isinstance(val, bytes) and "rules" in val.decode("utf8"):
						rules = info[idx + 1]
						for rule in rules:
							key = rule[0].decode("utf8")
							existing_rules[key] = {"time_bucket": rule[1], "aggregation": rule[2].decode("utf8")}

				for rule in metric.downsampling:
					retention, retention_time, aggregation = rule
					time_bucket = get_time_bucket_duration(retention)
					key = f"{orig_key}:{retention}"  # pylint: disable=loop-invariant-statement
					cmd = f"TS.CREATE {key} RETENTION {retention_time} LABELS node_name {node_name} worker_num {worker_num}"
					try:  # pylint: disable=loop-try-except-usage
						client.execute_command(cmd)
					except RedisResponseError as err:  # pylint: disable=loop-invariant-statement
						if str(err) != "TSDB: key already exists":
							raise

					create = True
					cur_rule = existing_rules.get(key)
					if cur_rule:
						if time_bucket == cur_rule.get("time_bucket") and aggregation.lower() == cur_rule["aggregation"].lower():
							create = False
						else:
							cmd = f"TS.DELETERULE {orig_key} {key}"
							client.execute_command(cmd)

					if create:
						cmd = f"TS.CREATERULE {orig_key} {key} AGGREGATION {aggregation} {time_bucket}"
						logger.debug("Redis cmd: %s", cmd)
						client.execute_command(cmd)


TIME_BUCKET_DURATIONS_MS = {
	"second": 1000,
	"minute": 60 * 1000,
	"hour": 3600 * 1000,
	"day": 24 * 3600 * 1000,
	"week": 7 * 24 * 3600 * 1000,
	"month": 30 * 24 * 3600 * 1000,
	"year": 365 * 24 * 3600 * 1000,
}


def get_time_bucket_duration(name: str) -> int:
	duration_ms = TIME_BUCKET_DURATIONS_MS.get(name)
	if duration_ms is None:
		raise ValueError(f"Invalid name: {name}")
	return duration_ms


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
	),
)


class StatisticsMiddleware(BaseHTTPMiddleware):  # pylint: disable=abstract-method
	def __init__(self, app: FastAPI, profiler_enabled: bool = False, log_func_stats: bool = False) -> None:
		super().__init__(app)

		self._profiler_enabled = profiler_enabled
		self._log_func_stats = log_func_stats
		self._write_callgrind_file = True
		self._profile_methods: Dict[str, str] = {
			"BackendManager._executeMethod": "backend",
			"MySQL.execute": "mysql",
			"Response.render": "render",
			# "serialize": "opsi_serialize",
			# "deserialize": "opsi_deserialize",
		}

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		logger.trace("StatisticsMiddleware scope=%s", scope)
		loop = asyncio.get_running_loop()

		if scope["type"] not in ("http", "websocket"):
			await self.app(scope, receive, send)
			return

		start = time.perf_counter()
		contextvar_server_timing.set({})
		worker = Worker()

		# logger.debug("Client Addr: %s", contextvar_client_address.get())
		async def send_wrapper(message: Message) -> None:
			if scope["type"] == "http" and message["type"] == "http.response.start":
				# Start of response (first message / package)
				if worker.metrics_collector:
					loop.create_task(
						worker.metrics_collector.add_value(
							"worker:sum_http_request_number", 1, {"node_name": config.node_name, "worker_num": worker.worker_num}
						)
					)
					ip_addr = contextvar_client_address.get()
					if ip_addr:
						loop.create_task(
							worker.metrics_collector.add_value(
								"client:sum_http_request_number", 1, {"client_addr": ip_address_to_redis_key(ip_addr)}
							)
						)

				headers = MutableHeaders(scope=message)

				content_length = headers.get("Content-Length", None)
				if content_length is None:
					if scope["method"] != "OPTIONS" and 200 <= message.get("status", 500) < 300 and not scope.get("reverse_proxy"):
						logger.warning("Header 'Content-Length' missing: %s", message)
				elif worker.metrics_collector:
					loop.create_task(
						worker.metrics_collector.add_value(
							"worker:avg_http_response_bytes",
							int(content_length),
							{"node_name": config.node_name, "worker_num": worker.worker_num},
						)
					)

				server_timing = contextvar_server_timing.get()
				server_timing["request_processing"] = int(1000 * (time.perf_counter() - start))
				headers.append("Server-Timing", ",".join([f"{k};dur={v:.3f}" for k, v in server_timing.items()]))

			logger.trace(message)
			await send(message)

			if scope["type"] == "http" and message["type"] == "http.response.body" and not message.get("more_body"):
				# End of response (last message / package)
				end = time.perf_counter()
				if worker.metrics_collector:
					loop.create_task(
						worker.metrics_collector.add_value(
							"worker:avg_http_request_duration",
							end - start,
							{"node_name": config.node_name, "worker_num": worker.worker_num},
						)
					)
				server_timing = contextvar_server_timing.get()
				server_timing["total"] = int(1000 * (time.perf_counter() - start))
				logger.info(
					"Server-Timing %s %s: %s",
					scope["method"],
					scope["full_path"],
					", ".join([f"{k}={v:.1f}ms" for k, v in server_timing.items()]),
				)

		await self.app(scope, receive, send_wrapper)
