# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:license: GNU Affero General Public License version 3
"""

import os
import re
import time
import asyncio
import threading
import psutil
import json
import copy
from contextvars import ContextVar
from typing import Dict, List
from ctypes import c_long
import yappi
from yappi import YFuncStats
from aredis.exceptions import ResponseError 

from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .logging import logger
from .worker import get_redis_client, get_metrics_collector, \
	contextvar_request_id, contextvar_client_address, contextvar_server_address, contextvar_server_timing
from .config import config
from .utils import Singleton, get_worker_processes, get_node_name, get_worker_num


def get_yappi_tag() -> int:
	tag = contextvar_request_id.get()
	if not tag:
		return -1
	return tag

GRAFANA_DATASOURCE_TEMPLATE = {
	"orgId": 1,
	"name": "opsiconfd",
	"type": "grafana-simple-json-datasource",
	"typeLogoUrl": "public/plugins/grafana-simple-json-datasource/img/simpleJson_logo.svg",
	"access": "proxy",
	"url": "https://opsiconfd:4447/metrics/grafana/",
	"password": "",
	"user": "",
	"database": "",
	"basicAuth": True,
	"isDefault": True,
	"jsonData": {
		"tlsSkipVerify": True
	},
	"basicAuthUser": "adminuser",
	"secureJsonData": {
		"basicAuthPassword": "adminuser"
	},
	"readOnly": False
}

GRAFANA_DASHBOARD_TEMPLATE = {
	"id": None,
	"uid": "opsiconfd_main",
	"annotations": {
		"list": [
			{
			"builtIn": 1,
			"datasource": "-- Grafana --",
			"enable": True,
			"hide": True,
			"iconColor": "rgba(0, 211, 255, 1)",
			"name": "Annotations & Alerts",
			"type": "dashboard"
			}
		]
	},
	"timezone": "",
	"title": "opsiconfd main dashboard",
	"editable": True,
	"gnetId": None,
	"graphTooltip": 0,
	"links": [],
	"panels": [],
	"refresh": "5s",
	"schemaVersion": 22,
	"version": 12,
	"style": "dark",
	"tags": [],
	"templating": {
		"list": []
	},
	"time": {
		"from": "now-5m",
		"to": "now"
	},
	"timepicker": {
		"refresh_intervals": [
			"1s",
			"5s",
			"10s",
			"30s",
			"1m",
			"5m",
			"15m",
			"30m",
			"1h",
			"2h",
			"1d"
		]
	},
	"variables": {
		"list": []
	}
}

GRAFANA_GRAPH_PANEL_TEMPLATE = {
	"aliasColors": {},
	"bars": False,
	"dashLength": 10,
	"dashes": False,
	"datasource": "opsiconfd",
	"description": "",
	"fill": 1,
	"fillGradient": 0,
	"gridPos": {
		"h": 12,
		"w": 8,
		"x": 0,
		"y": 0
	},
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
		"values": True
	},
	"lines": True,
	"linewidth": 1,
	"nullPointMode": "null",
	"options": {
		"dataLinks": []
	},
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
	"tooltip": {
		"shared": True,
		"sort": 0,
		"value_type": "individual"
	},
	"type": "graph",
	"xaxis": {
		"buckets": None,
		"mode": "time",
		"name": None,
		"show": True,
		"values": []
	},
	"yaxes": [
		{
			"format": "short",
			"label": None,
			"logBase": 1,
			"max": None,
			"min": None,
			"show": True
		},
		{
			"format": "short",
			"label": None,
			"logBase": 1,
			"max": None,
			"min": None,
			"show": True
		}
	],
	"yaxis": {
		"align": False,
		"alignLevel": None
	}
}

GRAFANA_HEATMAP_PANEL_TEMPLATE = {
  "datasource": "opsiconfd",
  "description": "",
  "gridPos": {
		"h": 12,
		"w": 8,
		"x": 0,
		"y": 0
	},
  "id": None,
  "targets": [],
  "timeFrom": None,
  "timeShift": None,
  "title": "Duration of remote procedure calls",
  "type": "heatmap",
  "heatmap": {},
  "cards": {
    "cardPadding": None,
    "cardRound": None
  },
  "color": {
    "mode": "opacity",
    "cardColor": "#73BF69",
    "colorScale": "sqrt",
    "exponent": 0.5,
    #"colorScheme": "interpolateSpectral",
    "min": None
  },
  "legend": {
    "show": False
  },
  "dataFormat": "timeseries",
  "yBucketBound": "auto",
  "reverseYBuckets": False,
  "xAxis": {
    "show": True
  },
  "yAxis": {
    "show": True,
    "format": "s",
    "decimals": 2,
    "logBase": 2,
    "splitFactor": None,
    "min": "0",
    "max": None
  },
  "xBucketSize": None,
  "xBucketNumber": None,
  "yBucketSize": None,
  "yBucketNumber": None,
  "tooltip": {
    "show": False,
    "showHistogram": False
  },
  "highlightCards": True,
  "hideZeroBuckets": False,
  "tooltipDecimals": 0
}

class GrafanaPanelConfig:
	def __init__(self, type="graph", title="", units=["short", "short"], decimals=0, stack=False):
		self.type = type
		self.title = title
		self.units = units
		self.decimals = decimals
		self.stack = stack
		self._template = ""
		if self.type == "graph":
			self._template = GRAFANA_GRAPH_PANEL_TEMPLATE
		elif self.type == "heatmap":
			self._template = GRAFANA_HEATMAP_PANEL_TEMPLATE
	
	def get_panel(self, id=1, x=0, y=0):
		panel = copy.deepcopy(self._template)
		panel["id"] = id
		panel["gridPos"]["x"] = x
		panel["gridPos"]["y"] = y
		panel["title"] = self.title
		if self.type == "graph":
			panel["stack"] = self.stack
			panel["decimals"] = self.decimals
			for i, unit in enumerate(self.units):
				panel["yaxes"][i]["format"] = unit
		elif self.type == "heatmap":
			panel["yAxis"]["format"] = self.units[0]
			panel["tooltipDecimals"] = self.decimals
		return panel

class Metric:
	def __init__(self, id: str, name: str, vars: List[str] = [], aggregation: str = "sum", retention: int = 0, zero_if_missing: bool = True,
				scope: str = "arbiter", server_timing_header_factor: int = None, grafana_config: GrafanaPanelConfig = None):
		assert aggregation in ("sum", "avg")
		assert scope in ("arbiter", "worker","client")
		self.id = id
		self.name = name
		self.vars = vars
		self.aggregation = aggregation
		self.retention = retention
		self.zero_if_missing = zero_if_missing
		self.scope = scope
		self.server_timing_header_factor = server_timing_header_factor
		self.grafana_config = grafana_config
		self.redis_key = self.redis_key_prefix = f"opsiconfd:stats:{id}"
		for var in self.vars:
			self.redis_key += ":{" + var + "}"
		name_regex = self.name
		for var in vars:
			name_regex = name_regex.replace('{' + var + '}', f"(?P<{var}>\S+)")
		self.name_regex = re.compile(name_regex)

	def get_redis_key(self, **kwargs):
		if not kwargs:
			return self.redis_key_prefix
		return self.redis_key.format(**kwargs)
	
	def get_name(self, **kwargs):
		return self.name.format(**kwargs)
	
	def get_vars_by_redis_key(self, redis_key):
		vars = {}
		if self.vars:
			values = redis_key[len(self.redis_key_prefix)+1:].split(':')
			for i, value in enumerate(values):
				vars[self.vars[i]] = value
		return vars
	
	def get_name_by_redis_key(self, redis_key):
		vars = self.get_vars_by_redis_key(redis_key)
		return self.get_name(**vars)

	def get_vars_by_name(self, name):
		return self.name_regex.fullmatch(name).groupdict()

class MetricsRegistry(metaclass=Singleton):
	def __init__(self):
		self._metrics_by_id = {}
	
	def register(self, *metric):
		for m in metric:
			self._metrics_by_id[m.id] = m

	def get_metric_ids(self):
		return list(self._metrics_by_id)
	
	def get_metrics(self, scope: str = None):

		# logger.notice("self._metrics_by_id.values(): %s", self._metrics_by_id.values())
		# logger.notice("self._metrics_by_id: %s", self._metrics_by_id)
		for metric in self._metrics_by_id.values():
			# logger.notice("METRIC ID: %s", metric.id)
			# logger.notice(metric.scope)
			# logger.notice(scope)
			if not scope or scope == metric.scope: # or metric.scope == "client":
				yield metric
			# yield metric

	def get_metric_by_id(self, id):
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
			if redis_key == metric.redis_key_prefix or redis_key.startswith(metric.redis_key_prefix + ':'):
				return metric
		raise ValueError(f"Metric with redis key '{redis_key}' not found")

metrics_registry = MetricsRegistry()

metrics_registry.register(
	Metric(
		id="worker:mem_allocated",
		name="Memory usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		scope="worker",
		grafana_config=GrafanaPanelConfig(title="Memory usage", units=["decbytes"], stack=True)
	),
	Metric(
		id="worker:cpu_percent",
		name="CPU usage of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		scope="worker",
		grafana_config=GrafanaPanelConfig(title="CPU usage", units=["percent"], decimals=1, stack=True)
	),
	Metric(
		id="worker:num_threads",
		name="Threads of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		scope="worker",
		grafana_config=GrafanaPanelConfig(title="Threads", units=["short"], decimals=0, stack=True)
	),
	Metric(
		id="worker:num_filehandles",
		name="Filehandles of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		scope="worker",
		grafana_config=GrafanaPanelConfig(title="Filehandles", units=["short"], decimals=0, stack=True)
	),
	Metric(
		id="worker:num_http_request",
		name="HTTP requests of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		scope="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP requests", units=["short"], decimals=0, stack=True)
	),
	Metric(
		id="worker:http_response_bytes",
		name="HTTP response size of worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		scope="worker",
		grafana_config=GrafanaPanelConfig(title="HTTP response size", units=["decbytes"], stack=True)
	),
	Metric(
		id="worker:http_request_duration",
		name="Duration of HTTP requests processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		aggregation="avg",
		retention=24 * 3600 * 1000,
		zero_if_missing=False,
		scope="worker",
		grafana_config=GrafanaPanelConfig(type="heatmap", title="Duration of HTTP requests", units=["s"], decimals=0)
	),
	Metric(
		id="client:num_http_request",
		name="HTTP requests of Client {client_addr}",
		vars=["client_addr"],
		retention=24 * 3600 * 1000,
		scope="client",
		grafana_config=GrafanaPanelConfig(title="Client requests", units=["short"], decimals=0, stack=False)
	),
	# Metric(
	# 	id="client:num_http_request:172.18.0.1",
	# 	name="HTTP requests of Client 172.18.0.1",
	# 	vars=["client_addr"],
	# 	retention=24 * 3600 * 1000,
	# 	scope="client",
	# 	grafana_config=GrafanaPanelConfig(title="Client requests", units=["short"], decimals=0, stack=True)
	# )
	# Metric(
	# 	id="client:num_http_request:172.18.0.4",
	# 	name="HTTP requests of Client 172.18.0.4",
	# 	vars=["client_addr"],
	# 	retention=24 * 3600 * 1000,
	# 	scope="worker",
	# 	grafana_config=GrafanaPanelConfig(title="Client requests", units=["short"], decimals=0, stack=True)
	# )
)


class MetricsCollector():
	def __init__(self, interval: int = 5):
		self._interval = interval
		self._node_name = get_node_name()
		self._worker_num = get_worker_num()
		self._proc = None
		self._values = {}
		self._values_lock = asyncio.Lock()
		self._last_timestamp = 0
	
	async def _fetch_values(self):
		if not self._proc:
			self._proc = psutil.Process()
		await self.add_value("worker:mem_allocated", self._proc.memory_info().rss, {"node_name": get_node_name(), "worker_num": get_worker_num()})
		await self.add_value("worker:cpu_percent", self._proc.cpu_percent(), {"node_name": get_node_name(), "worker_num": get_worker_num()})
		await self.add_value("worker:num_threads", self._proc.num_threads(), {"node_name": get_node_name(), "worker_num": get_worker_num()})
		await self.add_value("worker:num_filehandles", self._proc.num_fds(), {"node_name": get_node_name(), "worker_num": get_worker_num()})

	async def main_loop(self):

		# logger.error(metrics_registry.get_metric_by_id("worker:num_rpcs"))
		
		while True:
			# logger.notice(round(time.time()))
			# logger.notice(self._node_name)
			# logger.notice(self._worker_num)
			# logger.notice("VALUES: %s", self._values)

			# logger.warning(metrics_registry.get_metric_ids())

			cmd = None
			# logger.notice(self._scope)
			try:
				await self._fetch_values()
				# logger.notice(self._values)
				timestamp = round(time.time())*1000
				# timestamp = int(time.time() * 1000)
				
				for metric in metrics_registry.get_metrics():

					# logger.notice(metric.id)
					# logger.notice(metric.name)
					
					if not metric.id in self._values:
						continue


					if metric.scope == "client":
						# logger.notice(self._values)
						labels = {}
						for addr in self._values[metric.id]:

							# values = self._values[metric.id].get(key, {})
							logger.notice("ADDR: %s", addr)
							timestamps = self._values[metric.id][addr]
							logger.notice("timestamps: %s", timestamps)

								
							value = 0
							count = 0
							async with self._values_lock:

								values = self._values[metric.id].get(addr, {})
								logger.notice("VALUES: %s ", values)

								if not values and not metric.zero_if_missing:
									continue
								
								for ts in list(values):
									logger.error(ts)
									if ts <= timestamp:
										count += 1
										value += values[ts]
										del values[ts]

							if metric.aggregation == "avg" and count > 0:
								value /= count

							labels["client_addr"] = addr
							cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
							logger.notice(cmd)
							await self._execute_redis_command(cmd)
						
							# 	for key in self._values.get(metric.id, {}):
							# 		# logger.notice("KEY: %s", key)
							# 		values = self._values[metric.id].get(key, {})
							# 	# logger.notice("NEW VALUES: %s", values)
								
							# 	if not values and not metric.zero_if_missing:
							# 		continue
							# 	# logger.warning("IP: %s and VALUES: %s", addr, list(values))
							# 	for ts in list(values):
							# 		if ts <= timestamp:
							# 			count += 1
							# 			value += values[ts]
							# 			del values[ts]
							# if metric.aggregation == "avg" and count > 0:
							# 	value /= count
							# logger.error("IP: %s VALUE: %s", addr, value)
							# labels["client_addr"] = addr
							
							# cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
							# # logger.error(cmd)
							# await self._execute_redis_command(cmd)

					else:

						value = 0
						count = 0
						
						async with self._values_lock:
							for key in self._values.get(metric.id, {}):
								# logger.notice("V: %s", key)
								values = self._values[metric.id].get(key, {})
							# logger.notice("NEW VALUES: %s", values)
							if not values and not metric.zero_if_missing:
								continue
							for ts in list(values):
								if ts <= timestamp:
									count += 1
									value += values[ts]
									del values[ts]
						if metric.aggregation == "avg" and count > 0:
							value /= count

						labels = {}
						label_values = None
						
						for key in self._values[metric.id]:
							# logger.error(key)
							# logger.error(key.split(":"))
							# if metric.scope == "client":
							# 	logger.notice("KEY: %s", key)
							if label_values == None:
								label_values = (key.split(":"))
							else:
								label_values.append(key.split(":"))
						# if metric.scope == "client":
						# 	logger.notice("label_values: %s", label_values)
						for idx, var in enumerate(metric.vars):
							# if metric.scope == "client":
								# logger.notice("VAR: %s", var)
							labels[var] = label_values[idx]
						# logger.notice(label_values)
						# logger.notice(labels)
						
						# 	logger.notice(label_values)

						# logger.notice("##########: %s", labels)
						# logger.notice("LABEL_VALUES: %s", label_values)
						# logger.warning(metric.id)
						# logger.warning(metric.scope)
						# if self._scope == "worker": # and not metric.scope == "client":
						# 	labels = {
						# 		"node_name": self._node_name,
						# 		"worker_num": self._worker_num,
						# 	}
						# if metric.scope == "client":
						# 	logger.warning("SCOPE: CLIENT")
						# 	labels = {
						# 		"client_addr": contextvar_client_address.get()
						# 	}
						
						# for var in metric.vars:
						# 	labels = 
						cmd = self._redis_ts_cmd(metric, "ADD", value, timestamp, **labels)
						# if metric.scope == "client":
						# 	logger.warning("CMD: %s", cmd)
						await self._execute_redis_command(cmd)
			except Exception as exc:
				err = str(exc)
				if cmd:
					err += f" while executing redis command: {cmd}"
				logger.error(err, exc_info=True)
				if err.lower().startswith("unknown command"):
					logger.error("RedisTimeSeries module missing, metrics collector ending")
					break
			await asyncio.sleep(self._interval)

	def _redis_ts_cmd(self, metric: Metric, cmd: str, value: float, timestamp: int = None, **labels):
		timestamp = timestamp or "*"
		l_labels = []
		# logger.notice("LABELS REDIS: %s", labels)
		
		for key in labels:
			l_labels.extend([key, labels[key]])
		# logger.warning(self._values)
		# for var in metric.vars:
		# 	if not var in labels:
		# 		raise ValueError(f"No value for var {var} provided")
		# 	l_labels.extend([var, labels[var]])
		# logger.notice(metric.get_redis_key(**labels))
		if cmd == "ADD":
			cmd = ["TS.ADD", metric.get_redis_key(**labels), timestamp, value, "RETENTION", metric.retention, "LABELS"] + l_labels
		elif cmd == "INCRBY":
			cmd = ["TS.INCRBY", metric.get_redis_key(**labels), value, timestamp, "RETENTION", metric.retention, "LABELS"] + l_labels
		else:
			raise ValueError(f"Invalid command {cmd}")
		return " ".join([ str(x) for x in cmd ])

	async def _execute_redis_command(self, cmd, max_tries=2):
		# logger.notice("List: %s", cmd)
		if type(cmd) is list:
			# logger.notice("!!!")
			cmd = " ".join([ str(x) for x in cmd ])
		# logger.warning(cmd.split(" "))
		# logger.warning(cmd.split(" ")[2])
		# test = cmd.split(" ") 
		# test[2] = "123"
		# logger.warning(test)
		# logger.debug("Executing redis command: %s", cmd)
		# logger.notice("str: %s", cmd)
		for trynum in range(1, max_tries + 1):
			try:
				# logger.error(trynum)
				redis = await get_redis_client()
				if trynum > 1:
					cmd = cmd.split(" ")
					cmd[2] = timestamp = (round(time.time())*1000)+1
					# logger.error(time.time())
					# logger.error(cmd)
					cmd = " ".join([ str(x) for x in cmd ])
				return await redis.execute_command(cmd)
			except ResponseError:
				if trynum >= max_tries:
					raise
	
	#def add_value(self, metric: Metric, value: float, timestamp: int = None, **kwargs):
	async def add_value(self, metric_id: str, value: float, labels: dict = {}, timestamp: int = None):
		metric = metrics_registry.get_metric_by_id(metric_id)
		# logger.notice(metric_id)
		key_string = ""
		for var in metric.vars:
			if not key_string: 
				key_string = labels[var]
			else:
				key_string = f"{key_string}:{labels[var]}"
		# logger.notice(metric)
		# logger.notice(metric_id)
		# logger.notice(l_labels)
		# logger.notice(f"KEYSTRING: {key_string}")	

		if metric.server_timing_header_factor:
			server_timing = contextvar_server_timing.get()
			if type(server_timing) is dict:
				# Only if dict (initialized)
				server_timing[metric_id.split(':')[-1]] = value * metric.server_timing_header_factor
				contextvar_server_timing.set(server_timing)
		if not timestamp:
			timestamp = int(round(time.time()*1000))
		async with self._values_lock:
			# if metric_id == "worker:num_http_request":
				# logger.warning("VALUES: %s", self._values)
			#key = json.dumps(kwargs, sort_keys=True)
			if not metric_id in self._values:
				self._values[metric_id] = {}
			if not key_string in self._values[metric_id]:
				self._values[metric_id][key_string] = {}
			if not timestamp in self._values[metric_id][key_string]:
				self._values[metric_id][key_string][timestamp] = 0
			self._values[metric_id][key_string][timestamp] += value
			# logger.warning("VALUES: %s", self._values)

class StatisticsMiddleware(BaseHTTPMiddleware):
	def __init__(self, app: ASGIApp, profiler_enabled=False, log_func_stats=False) -> None:
		super().__init__(app)

		logger.warning("WORKER: %s", get_worker_num())
		logger.warning("NODE: %s" ,get_node_name())
		
		self._profiler_enabled = profiler_enabled
		self._log_func_stats = log_func_stats
		self._profile_methods: Dict[str, str] = {
			"BackendManager._executeMethod": "backend",
			"MySQL.execute": "mysql",
			"Response.render": "render",
			#"serialize": "opsi_serialize",
			#"deserialize": "opsi_deserialize",
		}
		if self._profiler_enabled:
			yappi.set_tag_callback(get_yappi_tag)
			yappi.set_clock_type("wall")
			# TODO: Schedule some kind of periodic profiler cleanup with clear_stats()
			yappi.start()

	def yappi(self, scope):
		# https://github.com/sumerc/yappi/blob/master/doc/api.md

		tag = get_yappi_tag()
		if tag == -1:
			return

		#yappi.get_func_stats({"tag": tag}).sort('ttot', sort_order="asc").debug_print()

		max_stats = 500
		if self._log_func_stats:
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------")
			logger.essential(f"{scope['request_id']} - {scope['client'][0]} - {scope['method']} {scope['path']}")
			logger.essential(f"{'module':<45} | {'function':<60} | {'calls':>5} | {'total time':>10}")
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------")
			func_stats = yappi.get_func_stats({"tag": tag}).sort("ttot", sort_order="desc")
			for stat_num, stat in enumerate(func_stats):
				module = re.sub(r".*(site-packages|python3\.\d|python-opsi)/", "", stat.module)
				logger.essential(f"{module:<45} | {stat.name:<60} | {stat.ncall:>5} |   {stat.ttot:0.6f}")
				if stat_num >= max_stats:
					break
			logger.essential("---------------------------------------------------------------------------------------------------------------------------------")

		func_stats: Dict[str, YFuncStats] = {
			stat_name: yappi.get_func_stats({"name": function, "tag": tag})
			for function, stat_name in self._profile_methods.items()
		}
		server_timing = {}
		for stat_name, stats in func_stats.items():
			if not stats.empty():
				server_timing[stat_name] = stats.pop().ttot * 1000
		return server_timing

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		logger.trace(f"StatisticsMiddleware {scope}")
		# logger.warning(scope)
		if scope["type"] not in ("http", "websocket"):
			await self.app(scope, receive, send)
			return
		
		start = time.perf_counter()
		request_id = id(scope)
		# Longs on Windows are only 32 bits, but memory adresses on 64 bit python are 64 bits
		request_id = abs(c_long(request_id).value) # Ensure it fits inside a long, truncating if necessary
		scope['request_id'] = request_id
		contextvar_request_id.set(request_id)
		contextvar_client_address.set(scope["client"][0])
		contextvar_server_address.set(scope["server"][0])
		contextvar_server_timing.set({})

		

		# logger.notice(contextvar_client_address.get())

		# get_metrics_collector()._redis_ts_cmd("client:client_addr")

		# async client_stat():
		# client_metrics = metrics_registry.get_metrics(scope="client")
		# for metric in client_metrics:
		# 	logger.notice(metric)
		# 	logger.notice(metric.id)
		# 	labels = {
		# 		"client_addr": contextvar_client_address.get()
		# 	}
		# 	timestamp = round(time.time())*1000
		# 	value = 0
		# 	count = 0
		# 	async with asyncio.Lock():
		# 		values = metric.vars.get(metric.id, {})
		# 		if not values and not metric.zero_if_missing:
		# 			continue
		# 		for ts in list(values):
		# 			if ts <= timestamp:
		# 				count += 1
		# 				value += values[ts]
		# 				del values[ts]
		# 	if metric.aggregation == "avg" and count > 0:
		# 		value /= count
		# 	cmd = get_metrics_collector()._redis_ts_cmd(metric, "ADD", 1, timestamp, **labels)
		# 	await get_metrics_collector()._execute_redis_command(cmd)
		# test = contextvar_client_address.get()
		# metrics_registry.register(
		# 	Metric(
		# 		id="client:num_http_request:{test}",
		# 		name="HTTP requests of Client {test}",
		# 		vars=["client_addr"],
		# 		retention=24 * 3600 * 1000,
		# 		scope="client",
		# 		grafana_config=GrafanaPanelConfig(title="Client requests", units=["short"], decimals=0, stack=True)
		# 	)
		# )
		
		# await client_stat()
		logger.warning(scope)
		logger.error(contextvar_client_address.get())
		async def send_wrapper(message: Message) -> None:
			await get_metrics_collector().add_value("worker:num_http_request", 1, {"node_name": get_node_name(), "worker_num": get_worker_num()})
			# if not scope["path"] == "/metrics/grafana/query":
			await get_metrics_collector().add_value("client:num_http_request", 1, {"client_addr": contextvar_client_address.get()})

			# await get_metrics_collector().add_value("client:client_addr", 1)
			# await get_metrics_collector().add_value(f"client:client_addr:{contextvar_client_address.get()}", 1)
			if message["type"] == "http.response.start":
				headers = MutableHeaders(scope=message)
				server_timing = contextvar_server_timing.get() or {}
				if self._profiler_enabled:
					server_timing.update(self.yappi(scope))
				if server_timing:
					server_timing = [f"{k};dur={v:.3f}"	for k, v in server_timing.items()]
					headers.append("Server-Timing", ','.join(server_timing))
			logger.trace(message)
			await send(message)
			end = time.perf_counter()
			if scope["type"] == "http":
				if "body" in message:
					await get_metrics_collector().add_value("worker:http_response_bytes", len(message['body']), {"node_name": get_node_name(), "worker_num": get_worker_num()})
				await get_metrics_collector().add_value("worker:http_request_duration", end - start, {"node_name": get_node_name(), "worker_num": get_worker_num()})
				

		await self.app(scope, receive, send_wrapper)
