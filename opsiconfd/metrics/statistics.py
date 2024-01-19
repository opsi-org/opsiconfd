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

import yappi  # type: ignore[import]
from fastapi import FastAPI
from redis import ResponseError as RedisResponseError
from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send

from opsiconfd import contextvar_request_id, contextvar_server_timing
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.metrics.registry import MetricsRegistry, NodeMetric, WorkerMetric
from opsiconfd.redis import redis_client
from opsiconfd.worker import Worker


def get_yappi_tag() -> int:
	if not contextvar_request_id:
		return 0
	return contextvar_request_id.get() or 0


def setup_metric_downsampling() -> None:  # pylint: disable=too-many-locals, too-many-branches, too-many-statements
	client = redis_client()
	for metric in MetricsRegistry().get_metrics():
		is_worker_metric = isinstance(metric, WorkerMetric)
		is_node_metric = isinstance(metric, NodeMetric)

		if not metric.downsampling:
			continue

		iterations = 1
		if is_worker_metric:
			iterations = config.workers

		for iteration in range(iterations):
			node_name = config.node_name
			worker_num = None
			if is_worker_metric:
				worker_num = iteration + 1

			logger.debug("Iteration=%s, node_name=%s, worker_num=%s", iteration, node_name, worker_num)

			orig_key = None
			cmd = None
			if is_worker_metric:
				orig_key = metric.redis_key.format(node_name=node_name, worker_num=worker_num)
				cmd = f"TS.CREATE {orig_key} RETENTION {metric.retention} LABELS node_name {node_name} worker_num {worker_num}"
			elif is_node_metric:
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
			existing_rules: dict[str, dict[str, str]] = {}
			for idx, val in enumerate(info):
				if isinstance(val, bytes) and "rules" in val.decode("utf8"):
					rules = info[idx + 1]
					for rule in rules:
						key = rule[0].decode("utf8")
						existing_rules[key] = {"time_bucket": rule[1], "aggregation": rule[2].decode("utf8")}

			for rule in metric.downsampling:
				retention, retention_time, aggregation = rule
				time_bucket = get_time_bucket_duration(retention)
				key = f"{orig_key}:{retention}"
				if is_worker_metric:
					cmd = f"TS.CREATE {key} RETENTION {retention_time} LABELS node_name {node_name} worker_num {worker_num}"
				elif is_node_metric:
					cmd = f"TS.CREATE {key} RETENTION {retention_time} LABELS node_name {node_name}"
				else:
					cmd = f"TS.CREATE {key} RETENTION {retention_time}"

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


class StatisticsMiddleware:  # pylint: disable=too-few-public-methods
	def __init__(self, app: FastAPI, profiler_enabled: bool = False, log_func_stats: bool = False) -> None:
		self.app = app
		self._profiler_enabled = profiler_enabled
		self._log_func_stats = log_func_stats
		self._write_callgrind_file = True

		if self._profiler_enabled:
			yappi.set_tag_callback(get_yappi_tag)
			yappi.set_clock_type("wall")
			# TODO: Schedule some kind of periodic profiler cleanup with clear_stats()
			yappi.start()

	def yappi(self, scope: Scope) -> None:
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
			)
			logger.essential(f"{scope['request_id']} - {scope['client'][0]} - {scope['method']} {scope['path']}")
			logger.essential(f"{'module':<55} | {'function':<45} | {'calls':>5} | {'total time':>10} | {'nosub time':>10}")
			logger.essential(
				"---------------------------------------------------------------------------------------------------------------------------------"
			)
			regex = re.compile(r".+(site-packages|python3\.\d|python-opsi)/")
			# sort: ncall / ttot / tsub / tavg
			for stat_num, stat in enumerate(func_stats.sort("ttot", sort_order="asc")):
				module = regex.sub("", stat.module)
				logger.essential(f"{module:<55} | {stat.name:<45} | {stat.ncall:>5} |   {stat.ttot:0.6f} |   {stat.tsub:0.6f}")
				if stat_num >= 500:
					break
			logger.essential(
				"---------------------------------------------------------------------------------------------------------------------------------"
			)

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		logger.trace("StatisticsMiddleware scope=%s", scope)

		if scope["type"] not in ("http", "websocket"):
			await self.app(scope, receive, send)
			return

		start = time.perf_counter()
		contextvar_server_timing.set({})
		worker = Worker.get_instance()

		# logger.debug("Client Addr: %s", contextvar_client_address.get())
		async def send_wrapper(message: Message) -> None:
			if scope["type"] == "http" and message["type"] == "http.response.start":
				# Start of response (first message / package)
				if worker.metrics_collector:
					await worker.metrics_collector.add_value("worker:sum_http_request_number", 1)

				headers = MutableHeaders(scope=message)

				content_length = headers.get("Content-Length", None)
				if content_length is None:
					if scope["method"] != "OPTIONS" and 200 <= message.get("status", 500) < 300 and not scope.get("reverse_proxy"):
						logger.warning("Header 'Content-Length' missing: %s", message)
				elif worker.metrics_collector:
					await worker.metrics_collector.add_value("worker:avg_http_response_bytes", int(content_length))

				server_timing = contextvar_server_timing.get()
				server_timing["request_processing"] = int(1000 * (time.perf_counter() - start))
				headers.append("Server-Timing", ",".join([f"{k};dur={v:.3f}" for k, v in server_timing.items()]))
				if self._profiler_enabled:
					self.yappi(scope)

			logger.trace(message)
			await send(message)

			if scope["type"] == "http" and message["type"] == "http.response.body" and not message.get("more_body"):
				# End of response (last message / package)
				end = time.perf_counter()
				if worker.metrics_collector:
					await worker.metrics_collector.add_value("worker:avg_http_request_duration", end - start)
				server_timing = contextvar_server_timing.get()
				server_timing["total"] = int(1000 * (time.perf_counter() - start))
				logger.info(
					"Server-Timing %s %s: %s",
					scope["method"],
					scope["full_path"],
					", ".join([f"{k}={v:.1f}ms" for k, v in server_timing.items()]),
				)

		await self.app(scope, receive, send_wrapper)
