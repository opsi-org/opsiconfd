# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
statistics
"""

import asyncio
import time
from typing import Dict

from fastapi import FastAPI
from redis import ResponseError as RedisResponseError
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import Message, Receive, Scope, Send

from .. import contextvar_client_address, contextvar_server_timing
from ..config import config
from ..logging import logger
from ..utils import ip_address_to_redis_key, redis_client
from ..worker import Worker
from .registry import MetricsRegistry


def setup_metric_downsampling() -> None:  # pylint: disable=too-many-locals, too-many-branches, too-many-statements

	with redis_client() as client:
		for metric in MetricsRegistry().get_metrics():
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
		worker = Worker.get_instance()

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
