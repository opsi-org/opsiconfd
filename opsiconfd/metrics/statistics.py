# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
statistics
"""

import re
import time
from collections.abc import Iterator
from typing import Any

from opsiconfd.backend import get_unprotected_backend

try:
	import yappi
except ImportError:
	yappi = None
from fastapi import FastAPI
from redis import Redis
from redis import ResponseError as RedisResponseError
from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send

from opsiconfd import contextvar_request_id, contextvar_server_timing
from opsiconfd.config import config, get_server_role
from opsiconfd.logging import logger
from opsiconfd.metrics.metric import DepotMetric, Metric, NodeMetric, WorkerMetric
from opsiconfd.metrics.registry import MetricsRegistry
from opsiconfd.redis import decode_redis_result, redis_client
from opsiconfd.worker import Worker


def get_yappi_tag() -> int:
	if not contextvar_request_id:
		return 0
	return contextvar_request_id.get() or 0


def _time_series_info(client: Redis, key: str) -> dict[str, Any]:
	"""Return normalized RedisTimeSeries information for a key."""
	result = decode_redis_result(client.execute_command("TS.INFO", key))
	if isinstance(result, dict):
		return result
	return dict(zip(result[::2], result[1::2], strict=True))


def _ensure_time_series(client: Redis, key: str, retention: int, labels: dict[str, str | int]) -> dict[str, Any]:
	"""Create a time series or update its retention and return existing information."""
	command: list[Any] = ["TS.CREATE", key, "RETENTION", retention]
	if labels:
		command.append("LABELS")
		for name, value in labels.items():
			command.extend((name, value))

	try:
		client.execute_command(*command)
		return {}
	except RedisResponseError as err:
		if str(err) != "TSDB: key already exists":
			raise

	info = _time_series_info(client, key)
	if info.get("retentionTime") != retention:
		client.execute_command("TS.ALTER", key, "RETENTION", retention)
	return info


def _metric_label_sets(metric: Metric, node_name: str, depot_ids: list[str]) -> Iterator[dict[str, str | int]]:
	"""Yield label sets for every time series represented by a metric."""
	if isinstance(metric, WorkerMetric):
		for worker_num in range(1, config.workers + 1):
			yield {"node_name": node_name, "worker_num": worker_num}
		return
	if isinstance(metric, NodeMetric):
		yield {"node_name": node_name}
		return
	if isinstance(metric, DepotMetric):
		for depot_id in depot_ids:
			yield {"depot_id": depot_id}
		return
	yield {}


def setup_metric_downsampling() -> None:
	"""Reconcile configured metric time series and downsampling rules."""
	if get_server_role() != "configserver":
		return

	node_name = config.node_name
	depot_ids = []
	try:
		depot_ids = get_unprotected_backend().host_getIdents(returnType="str", type="OpsiDepotserver")
	except Exception as err:
		logger.error("Failed to get depot ids: %s", err, exc_info=True)

	client = redis_client()
	for metric in MetricsRegistry().get_metrics():
		if not metric.downsampling:
			continue

		for labels in _metric_label_sets(metric, node_name, depot_ids):
			orig_key = metric.get_redis_key(**labels)
			info = _ensure_time_series(client, orig_key, metric.retention, labels)
			existing_rules = {rule[0]: (rule[1], rule[2].lower()) for rule in info.get("rules", [])}
			desired_keys: set[str] = set()

			for name, retention, aggregation in metric.downsampling:
				key = f"{orig_key}:{name}"
				desired_keys.add(key)
				_ensure_time_series(client, key, retention, labels)

				desired_rule = (get_time_bucket_duration(name), aggregation.value.lower())
				if existing_rules.get(key) == desired_rule:
					continue
				if key in existing_rules:
					client.execute_command("TS.DELETERULE", orig_key, key)
				client.execute_command("TS.CREATERULE", orig_key, key, "AGGREGATION", desired_rule[1], desired_rule[0])

			for key in existing_rules.keys() - desired_keys:
				if key.startswith(f"{orig_key}:"):
					client.execute_command("TS.DELETERULE", orig_key, key)
					client.unlink(key)


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


class StatisticsMiddleware:
	def __init__(self, app: FastAPI) -> None:
		self.app = app
		self._profiler_enabled = "yappi" in config.profiler
		self._log_func_stats = self._profiler_enabled
		self._write_callgrind_file = True

		if self._profiler_enabled:
			if not yappi:
				logger.error("yappi module not found, disabling profiler")
				self._profiler_enabled = False
			else:
				yappi.set_tag_callback(get_yappi_tag)
				yappi.set_clock_type("wall")
				# TODO: Schedule some kind of periodic profiler cleanup with clear_stats()
				yappi.start()

	def yappi(self, scope: Scope) -> None:
		# https://github.com/sumerc/yappi/blob/master/doc/api.md
		if not yappi:
			return

		tag = get_yappi_tag()
		if tag <= 0:
			return

		func_stats = yappi.get_func_stats(filter={"tag": tag})
		# func_stats.sort("ttot", sort_order="desc").debug_print()

		if self._write_callgrind_file:
			# Use i.e. kcachegrind to visualize
			func_stats.save(f"/tmp/callgrind.out.opsiconfd-yappi-{tag}", type="callgrind")

		if self._log_func_stats:
			logger.essential(
				"---------------------------------------------------------------------------------------------------------------------------------"
			)
			logger.essential(f"{scope['request_id']} - {scope['client'][0]} - {scope.get('method')} {scope['path']}")
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

		scope_type = scope["type"]
		if scope_type not in ("http", "websocket"):
			await self.app(scope, receive, send)
			return

		start = time.perf_counter()
		contextvar_server_timing.set({})
		worker = Worker.get_instance()

		if scope_type == "http" and worker.metrics_collector:
			try:
				await worker.metrics_collector.add_value(
					"worker:avg_http_request_bytes", int(scope["request_headers"].get("Content-Length") or 0)
				)
			except Exception as err:
				logger.error("Failed to add avg_http_request_bytes value to metrics collector: %s", err)

		# logger.debug("Client Addr: %s", contextvar_client_address.get())
		async def send_wrapper(message: Message) -> None:
			message_type = message["type"]
			if scope_type == "http" and message_type == "http.response.start":
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

				server_timing = contextvar_server_timing.get() or {}
				server_timing["request_processing"] = int(1000 * (time.perf_counter() - start))
				headers.append("Server-Timing", ",".join([f"{k};dur={v:.3f}" for k, v in server_timing.items()]))
				if self._profiler_enabled:
					self.yappi(scope)
			elif scope_type == "websocket" and message_type == "websocket.accept":
				if self._profiler_enabled:
					self.yappi(scope)

			logger.trace(message)
			await send(message)

			if scope_type == "http" and message_type == "http.response.body" and not message.get("more_body"):
				# End of response (last message / package)
				end = time.perf_counter()
				if worker.metrics_collector:
					await worker.metrics_collector.add_value("worker:avg_http_request_duration", end - start)
				server_timing = contextvar_server_timing.get() or {}
				server_timing["total"] = int(1000 * (time.perf_counter() - start))
				logger.info(
					"Server-Timing %s %s: %s",
					scope["method"],
					scope["path"],
					", ".join([f"{k}={v:.1f}ms" for k, v in server_timing.items()]),
				)

		await self.app(scope, receive, send_wrapper)
