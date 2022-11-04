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
import time
from typing import TYPE_CHECKING, Any, Dict, Tuple

import psutil
from redis import ResponseError

from .. import contextvar_server_timing
from ..config import config
from ..logging import logger
from ..utils import async_redis_client
from .registry import Metric, MetricsRegistry

if TYPE_CHECKING:
	from ..worker import Worker


class MetricsCollector:  # pylint: disable=too-many-instance-attributes
	_metric_subjects: Tuple = ()

	def __init__(self) -> None:
		self._interval = 5
		self._node_name = config.node_name
		self._values: Dict[str, Dict[str, Dict[int, Any]]] = {}
		self._values_lock = asyncio.Lock()
		self._last_timestamp = 0
		self._should_stop = False

	def stop(self) -> None:
		self._should_stop = True

	def _get_timestamp(self) -> int:
		# Return unix timestamp (UTC) in millis
		return int(time.time() * 1000)

	async def _fetch_values(self) -> None:
		asyncio.get_running_loop().create_task(self.add_value("node:avg_load", psutil.getloadavg()[0], {"node_name": self._node_name}))

	def _init_vars(self) -> None:
		for metric in MetricsRegistry().get_metrics(*self._metric_subjects):  # pylint: disable=loop-global-usage
			if metric.zero_if_missing != "continuous":
				continue

			keys = []
			for var in metric.vars:
				if hasattr(self, var):
					keys.append(str(getattr(self, var)))
				elif hasattr(self, f"_{var}"):
					keys.append(str(getattr(self, f"_{var}")))
				else:
					break

			if not keys:
				continue

			key_string = ":".join(keys)
			if metric.id not in self._values:
				self._values[metric.id] = {}
			if key_string not in self._values[metric.id]:
				self._values[metric.id][key_string] = {}

	async def main_loop(self) -> None:  # pylint: disable=too-many-branches,too-many-locals
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
					for metric in MetricsRegistry().get_metrics(*self._metric_subjects):  # pylint: disable=loop-global-usage
						if metric.id not in self._values:
							continue

						for key_string in list(self._values.get(metric.id, {})):
							value = 0.0
							count = 0
							insert_zero_timestamp = 0
							for tsp in list(self._values[metric.id].get(key_string, {})):
								if self._values[metric.id][key_string][tsp] is None:  # pylint: disable=loop-invariant-statement
									# Marker, insert a zero before adding new values
									insert_zero_timestamp = tsp
									self._values[metric.id][key_string].pop(tsp)
									continue
								if tsp <= timestamp:
									count += 1
									value += self._values[metric.id][key_string].pop(tsp)

							if count == 0:
								if not metric.zero_if_missing:  # pylint: disable=loop-invariant-statement
									continue
								if not insert_zero_timestamp and metric.zero_if_missing == "one":  # pylint: disable=loop-invariant-statement
									del self._values[metric.id][key_string]

							if metric.aggregation == "avg" and count > 0:  # pylint: disable=loop-invariant-statement
								value /= count

							label_values = key_string.split(":")
							labels = {var: label_values[idx] for idx, var in enumerate(metric.vars)}  # pylint: disable=loop-invariant-statement

							if insert_zero_timestamp:
								cmds.append(self._redis_ts_cmd(metric, "ADD", 0, insert_zero_timestamp, **labels))

							cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
							logger.debug("Redis ts cmd %s", cmd)
							cmds.append(cmd)

				try:  # pylint: disable=loop-try-except-usage
					await self._execute_redis_command(*cmds)
				except ResponseError as err:  # pylint: disable=broad-except
					if str(err).lower().startswith("unknown command"):  # pylint: disable=loop-invariant-statement
						logger.error("RedisTimeSeries module missing, metrics collector ending")
						return
					logger.error("%s while executing redis commands: %s", err, cmds, exc_info=True)

			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
			for _ in range(self._interval):
				if self._should_stop:
					return
				await asyncio.sleep(1)  # pylint: disable=dotted-import-in-loop

	@staticmethod
	def _redis_ts_cmd(metric: Metric, cmd: str, value: float, timestamp: int = None, **labels: str) -> str:
		timestamp_str: str = str(timestamp or "*")
		# ON_DUPLICATE SUM needs Redis Time Series >= 1.4.6
		if cmd == "ADD":
			ts_cmd = [  # pylint: disable=use-tuple-over-list
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
			ts_cmd = [  # pylint: disable=use-tuple-over-list
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
				logger.debug("Adding redis command to pipe: %s", a_cmd)
				await pipe.execute_command(a_cmd)
			logger.debug("Executing redis pipe (%d commands)", len(cmd))
			return await pipe.execute()

	async def add_value(self, metric_id: str, value: float, labels: dict = None, timestamp: int = None) -> None:
		if labels is None:
			labels = {}
		metric = MetricsRegistry().get_metric_by_id(metric_id)
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

	async def _fetch_values(self) -> None:
		asyncio.get_running_loop().create_task(self.add_value("node:avg_load", psutil.getloadavg()[0], {"node_name": self._node_name}))


class WorkerMetricsCollector(MetricsCollector):
	_metric_subjects = ("worker", "client")

	def __init__(self, worker: Worker) -> None:
		super().__init__()
		self.worker = worker
		self._proc: psutil.Process | None = None

	@property
	def worker_num(self) -> int:
		return self.worker.worker_num

	async def _fetch_values(self) -> None:
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
				asyncio.get_running_loop().create_task(  # pylint: disable=dotted-import-in-loop
					self.add_value(metric_id, value, {"node_name": self._node_name, "worker_num": self.worker_num})
				)
