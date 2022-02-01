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
from typing import Dict, Optional

import yappi  # type: ignore[import]
from yappi import YFuncStats
from redis import ResponseError as RedisResponseError

from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import contextvar_request_id, contextvar_client_address, contextvar_server_timing
from .logging import logger
from .worker import Worker
from .config import config
from .utils import redis_client, ip_address_to_redis_key
from .grafana import GrafanaPanelConfig
from .metrics import Metric, metrics_registry


def get_yappi_tag() -> int:
	return contextvar_request_id.get() or 0


def setup_metric_downsampling() -> None:  # pylint: disable=too-many-locals, too-many-branches, too-many-statements
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
				existing_rules: Dict[str, Dict[str, str]] = {}
				for idx, val in enumerate(info):
					if isinstance(val, bytes) and "rules" in val.decode("utf8"):
						rules = info[idx + 1]
						for rule in rules:
							key = rule[0].decode("utf8")
							# retention = key.split(":")[-1]
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


TIME_BUCKETS = {
	"second": 1000,
	"minute": 60 * 1000,
	"hour": 3600 * 1000,
	"day": 24 * 3600 * 1000,
	"week": 7 * 24 * 3600 * 1000,
	"month": 30 * 24 * 3600 * 1000,
	"year": 365 * 24 * 3600 * 1000,
}


def get_time_bucket(interval: str) -> int:
	time_bucket = TIME_BUCKETS.get(interval)
	if time_bucket is None:
		raise ValueError(f"Invalid interval: {interval}")
	return time_bucket


def get_time_bucket_name(time: int) -> Optional[str]:  # pylint: disable=redefined-outer-name
	time_bucket_name = None
	for name, t in TIME_BUCKETS.items():  # pylint: disable=invalid-name
		if time >= t:
			time_bucket_name = name
	return time_bucket_name


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
	def __init__(self, app: ASGIApp, profiler_enabled=False, log_func_stats=False) -> None:
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
		if self._profiler_enabled:
			yappi.set_tag_callback(get_yappi_tag)
			yappi.set_clock_type("wall")
			# TODO: Schedule some kind of periodic profiler cleanup with clear_stats()
			yappi.start()

	def yappi(self, scope):  # pylint: disable=inconsistent-return-statements
		# https://github.com/sumerc/yappi/blob/master/doc/api.md

		tag = get_yappi_tag()
		if tag <= 0:
			return

		func_stats = yappi.get_func_stats(filter={"tag": tag})
		# func_stats.sort("ttot", sort_order="desc").debug_print()

		if self._write_callgrind_file:
			# Use i.e. kcachegrind to visualize
			func_stats.save(f"/tmp/callgrind.out.opsiconfd-yappi-{tag}", type="callgrind")  # pylint: disable=no-member

		if self._log_func_stats:
			logger.essential(
				"---------------------------------------------------------------------------------------------------------------------------------"
			)  # pylint: disable=line-too-long
			logger.essential(f"{scope['request_id']} - {scope['client'][0]} - {scope['method']} {scope['path']}")
			logger.essential(f"{'module':<45} | {'function':<60} | {'calls':>5} | {'total time':>10}")
			logger.essential(
				"---------------------------------------------------------------------------------------------------------------------------------"
			)  # pylint: disable=line-too-long
			for stat_num, stat in enumerate(func_stats.sort("ttot", sort_order="desc")):
				module = re.sub(r".*(site-packages|python3\.\d|python-opsi)/", "", stat.module)
				logger.essential(f"{module:<45} | {stat.name:<60} | {stat.ncall:>5} |   {stat.ttot:0.6f}")
				if stat_num >= 500:
					break
			logger.essential(
				"---------------------------------------------------------------------------------------------------------------------------------"
			)  # pylint: disable=line-too-long

		func_stats: Dict[str, YFuncStats] = {
			stat_name: yappi.get_func_stats(filter={"name": function, "tag": tag}) for function, stat_name in self._profile_methods.items()
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
		worker = Worker()

		# logger.debug("Client Addr: %s", contextvar_client_address.get())
		async def send_wrapper(message: Message) -> None:
			if message["type"] == "http.response.start":
				# Start of response (first message / package)
				if worker.metrics_collector:
					loop.create_task(
						worker.metrics_collector.add_value(
							"worker:sum_http_request_number", 1, {"node_name": config.node_name, "worker_num": worker.worker_num}
						)
					)
					loop.create_task(
						worker.metrics_collector.add_value(
							"client:sum_http_request_number", 1, {"client_addr": ip_address_to_redis_key(contextvar_client_address.get())}
						)
					)

				headers = MutableHeaders(scope=message)

				content_length = headers.get("Content-Length", None)
				if content_length is None:
					if scope["method"] != "OPTIONS" and 200 <= message.get("status", 500) < 300:
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
				if self._profiler_enabled:
					server_timing.update(self.yappi(scope))
				server_timing["request_processing"] = int(1000 * (time.perf_counter() - start))
				headers.append("Server-Timing", ",".join([f"{k};dur={v:.3f}" for k, v in server_timing.items()]))

			logger.trace(message)
			await send(message)

			if message["type"] == "http.response.body" and not message.get("more_body"):
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
					scope["path"],
					", ".join([f"{k}={v:.1f}ms" for k, v in server_timing.items()]),
				)

		await self.app(scope, receive, send_wrapper)
