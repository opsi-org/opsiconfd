# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
metrics.collector
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import psutil
from redis import ResponseError

from opsiconfd.config import config
from opsiconfd.logging import get_logger
from opsiconfd.metrics.registry import Metric, MetricsRegistry, NodeMetric, WorkerMetric
from opsiconfd.redis import async_redis_client
from opsiconfd.utils import utc_timestamp

if TYPE_CHECKING:
	from opsiconfd.messagebus.websocket import MessagebusWebsocketStatistics
	from opsiconfd.worker import Worker

logger = get_logger("opsiconfd.metrics")


class MetricsCollector:  # pylint: disable=too-many-instance-attributes
	_metric_type = Metric

	def __init__(self) -> None:
		self._interval = 5
		self._values_lock = asyncio.Lock()
		self._last_timestamp = 0
		self._should_stop = False
		self._labels: dict[str, str] = {}
		self._metrics: dict[str, Metric] = {m.id: m for m in MetricsRegistry().get_metrics(self._metric_type)}
		self._values: dict[str, dict[int, Any]] = {metric_id: {} for metric_id in self._metrics}
		self._missing_metric_ids: list[str] = []
		self._enabled = config.collect_metrics

	def stop(self) -> None:
		self._should_stop = True

	def _get_timestamp(self) -> int:
		# Return unix timestamp (UTC) in millis
		return int(utc_timestamp() * 1000)

	async def _fetch_values(self) -> None:
		pass

	async def add_value(self, metric_id: str, value: float, timestamp: int | None = None) -> None:
		timestamp = timestamp or self._get_timestamp()

		logger.trace("add_value metric_id=%r, value=%r, timestamp=%r", metric_id, value, timestamp)

		async with self._values_lock:
			if timestamp not in self._values[metric_id]:
				self._values[metric_id][timestamp] = 0
			self._values[metric_id][timestamp] += value

	async def _write_values_to_redis(self) -> None:
		timestamp = self._get_timestamp()

		values: dict[str, list[float]] = {}
		# lock self._values as short as possible, to not block add_value
		async with self._values_lock:
			for metric_id, tspvals in self._values.items():
				values[metric_id] = [tspvals.pop(tsp) for tsp in list(tspvals) if tsp <= timestamp]

		cmds = []
		for metric_id, metric in self._metrics.items():
			vals = values.get(metric_id, [])
			value = sum(vals)
			count = len(vals)

			if count == 0:
				if not metric.zero_if_missing:
					continue
				if metric.zero_if_missing == "one":
					if metric_id in self._missing_metric_ids:
						# Marked as missing, a zero was inserted before, nothing to do
						continue
					# Mark as missing and insert one zero
					self._missing_metric_ids.append(metric_id)
				# If zero_if_missing == continuous always insert a zero
			else:
				if metric_id in self._missing_metric_ids:
					# Marked as missing, insert a zero before adding new values
					# because gaps in diagrams will be conneced with straight lines.
					last_timestamp = timestamp - self._interval * 1000
					cmds.append(self._redis_ts_cmd(metric, "ADD", 0, last_timestamp, **self._labels))
					self._missing_metric_ids.remove(metric_id)

			if metric.aggregation == "avg" and count > 0:
				value /= count

			cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **self._labels)
			logger.trace("Redis ts cmd %s", cmd)
			cmds.append(cmd)

		try:
			await self._execute_redis_command(*cmds)
		except ResponseError as err:  # pylint: disable=broad-except
			if str(err).lower().startswith("unknown command"):
				logger.error("RedisTimeSeries module missing, metrics collector ending")
				self.stop()
			logger.error("%s while executing redis commands: %s", err, cmds, exc_info=True)

	async def main_loop(self) -> None:
		while True:
			if self._enabled:
				try:
					await self._fetch_values()
					await self._write_values_to_redis()
				except Exception as err:  # pylint: disable=broad-except
					logger.error(err, exc_info=True)
			for _ in range(self._interval):
				if self._should_stop:
					return
				await asyncio.sleep(1)

	@staticmethod
	def _redis_ts_cmd(metric: Metric, cmd: str, value: float, timestamp: int | None = None, **labels: str) -> str:
		timestamp_str: str = str(timestamp or "*")
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
			]
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
			]
		else:
			raise ValueError(f"Invalid command {cmd}")
		return " ".join([str(x) for x in ts_cmd] + [p for pairs in labels.items() for p in pairs])

	@staticmethod
	async def _execute_redis_command(*cmd: str) -> Any:
		def str_cmd(cmd_obj: Any) -> str:
			if isinstance(cmd_obj, list):
				return " ".join([str(x) for x in cmd_obj])
			return cmd_obj

		redis = await async_redis_client()
		if len(cmd) == 1:
			return await redis.execute_command(str_cmd(cmd[0]))  # type: ignore[no-untyped-call]

		async with redis.pipeline(transaction=False) as pipe:
			for a_cmd in cmd:
				a_cmd = str_cmd(a_cmd)
				logger.trace("Adding redis command to pipe: %s", a_cmd)
				await pipe.execute_command(a_cmd)  # type: ignore[attr-defined]
			logger.trace("Executing redis pipe (%d commands)", len(cmd))
			return await pipe.execute()  # type: ignore[attr-defined]


class ManagerMetricsCollector(MetricsCollector):
	_metric_type = NodeMetric

	def __init__(self) -> None:
		super().__init__()
		self._labels = {"node_name": config.node_name}

	async def _fetch_values(self) -> None:
		await self.add_value("node:avg_load", psutil.getloadavg()[0])


statistics: MessagebusWebsocketStatistics | None = None  # pylint: disable=invalid-name


class WorkerMetricsCollector(MetricsCollector):
	_metric_type = WorkerMetric

	def __init__(self, worker: Worker) -> None:
		super().__init__()
		self._labels = {"node_name": worker.node_name, "worker_num": str(worker.worker_num)}
		self._worker = worker
		self._proc: psutil.Process | None = None
		self._last_messagebus_messages_sent = 0
		self._last_messagebus_messages_received = 0

		global statistics  # pylint: disable=global-statement,invalid-name
		# pylint: disable=invalid-name,import-outside-toplevel,redefined-outer-name
		from opsiconfd.messagebus.websocket import statistics

	@property
	def worker_num(self) -> int:
		return self._worker.worker_num

	async def _fetch_values(self) -> None:
		if not self._proc:
			self._proc = psutil.Process()

		for metric_id, value in (
			("worker:avg_mem_allocated", self._proc.memory_info().rss),
			("worker:avg_cpu_percent", self._proc.cpu_percent()),
			("worker:avg_thread_number", self._proc.num_threads()),
			("worker:avg_filehandle_number", self._proc.num_fds()),
			("worker:avg_connection_number", self._worker.get_connection_count()),
		):
			# Do not add 0-values
			if value:
				await self.add_value(metric_id, value)

		assert statistics

		value = statistics.messages_sent - self._last_messagebus_messages_sent
		if value:
			await self.add_value("worker:sum_messagebus_messages_sent", value)
			self._last_messagebus_messages_sent = statistics.messages_sent

		value = statistics.messages_received - self._last_messagebus_messages_received
		if value:
			await self.add_value("worker:sum_messagebus_messages_received", value)
			self._last_messagebus_messages_received = statistics.messages_received
