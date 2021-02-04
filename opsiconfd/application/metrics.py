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
:license: GNU Affero General Public License version 3
"""

import copy
import time
from datetime import datetime
from typing import List
from operator import itemgetter
from urllib.parse import urlparse
import aredis
import aiohttp

from pydantic import BaseModel # pylint: disable=no-name-in-module
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from ..logging import logger
from ..config import config
from ..server import get_internal_url
from ..worker import get_redis_client
from ..statistics import metrics_registry, get_time_bucket
from ..grafana import GRAFANA_DATASOURCE_TEMPLATE, GRAFANA_DASHBOARD_TEMPLATE

grafana_metrics_router = APIRouter()

def metrics_setup(app):
	app.include_router(grafana_metrics_router, prefix="/metrics/grafana")

async def get_workers():
	redis = await get_redis_client()
	workers = []
	async for redis_key in redis.scan_iter("opsiconfd:worker_registry:*"):
		redis_key = redis_key.decode("utf-8")
		workers.append({"node_name": redis_key.split(':')[-2], "worker_num": int(redis_key.split(':')[-1])})
	workers.sort(key=itemgetter("node_name", "worker_num"))
	return workers

async def get_nodes():
	return { worker["node_name"] for worker in await get_workers() }

async def get_clients(metric_id):
	redis = await get_redis_client()
	clients = []
	# TODO: IPv6 ?
	async for redis_key in redis.scan_iter(f"opsiconfd:stats:{metric_id}:*"):
		redis_key = redis_key.decode("utf-8")
		clients.append({"client_addr": redis_key.split(':')[-1]})
	clients.sort(key=itemgetter("client_addr"))
	return clients

@grafana_metrics_router.get('/?')
async def grafana_index():
	# should return 200 ok. Used for "Test connection" on the datasource config page.
	return None

@grafana_metrics_router.get("/dashboard")
async def grafana_dashboard(request: Request):  # pylint: disable=unused-argument
	auth = None
	headers = None
	url = urlparse(config.grafana_internal_url)
	if url.username is not None:
		if url.password is None:
			# Username only, assuming this is an api key
			logger.debug("Using api key for grafana authorization")
			headers = {"Authorization": f"Bearer {url.username}"}
		else:
			logger.debug("Using username %s and password grafana authorization", url.username)
			auth = aiohttp.BasicAuth(url.username, url.password)

	base_url = f"{url.scheme}://{url.netloc.split('@', 1)[-1]}"
	async with aiohttp.ClientSession(auth=auth, headers=headers) as session:
		json = GRAFANA_DATASOURCE_TEMPLATE
		json["url"] = f"{get_internal_url()}/metrics/grafana/"
		resp = await session.get(f"{base_url}/api/datasources/name/{json['name']}")
		if resp.status == 200:
			_id = (await resp.json())["id"]
			resp = await session.put(f"{base_url}/api/datasources/{_id}", json=json)
		else:
			resp = await session.post(f"{base_url}/api/datasources", json=json)

		if resp.status == 200:
			json = {
				"folderId": 0,
				"overwrite": True,
				"dashboard": await grafana_dashboard_config()
			}
			resp = await session.post(f"{base_url}/api/dashboards/db", json=json)
		else:
			logger.error("Failed to create grafana datasource: %s - %s", resp.status, await resp.text())
	return RedirectResponse(url=f"{config.grafana_external_url}/d/opsiconfd_main/opsiconfd-main-dashboard?kiosk=tv")


@grafana_metrics_router.get('/dashboard/config')
async def grafana_dashboard_config(): #  pylint: disable=too-many-locals
	workers = await get_workers()
	nodes = await get_nodes()
	clients = await get_clients("client:sum_http_request_number")

	dashboard = copy.deepcopy(GRAFANA_DASHBOARD_TEMPLATE)
	panels = []
	pos_x = 0
	pos_y = 0
	for panel_id, metric in enumerate(metrics_registry.get_metrics()):
		if not metric.grafana_config:
			continue
		panel_id += 1
		panel = metric.grafana_config.get_panel(id=panel_id, x=pos_x, y=pos_y)
		if metric.subject == "worker":
			for i, worker in enumerate(workers):
				panel["targets"].append({
					"refId": chr(65+i),
					"target": metric.get_name(node_name=worker["node_name"], worker_num=worker["worker_num"]),
					"type": "timeserie"
				})
		elif metric.subject == "node":
			for i, node_name in enumerate(nodes):
				panel["targets"].append({
					"refId": chr(65+i),
					"target": metric.get_name(node_name=node_name),
					"type": "timeserie"
				})
		elif metric.subject == "client":
			for i, client in enumerate(clients):
				panel["targets"].append({
					"refId": chr(65+i),
					"target": metric.get_name(client_addr=client["client_addr"]),
					"type": "timeserie"
				})
		panels.append(panel)
		pos_x += panel["gridPos"]["w"]
		if pos_x >= 24:
			pos_x = 0
			pos_y += panel["gridPos"]["h"]

	dashboard["panels"] = panels
	return dashboard

@grafana_metrics_router.get('/search')
@grafana_metrics_router.post('/search')
async def grafana_search():
	workers = await get_workers()
	nodes = await get_nodes()
	clients = await get_clients("client:sum_http_request_number")

	names = []
	for metric in metrics_registry.get_metrics():
		if metric.subject == "worker":
			for worker in workers:
				names.append(metric.get_name(**worker))
		elif metric.subject == "node":
			for node_name in nodes:
				names.append(metric.get_name(node_name=node_name))
		elif metric.subject == "client":
			for client in clients:
				names.append(metric.get_name(**client))
		else:
			names.append(metric.get_name())
	return sorted(names)

class GrafanaQueryTargetRange(BaseModel): #  pylint: disable=too-few-public-methods
	from_: str
	to: str
	raw: dict
	class Config: #  pylint: disable=too-few-public-methods
		fields = {
			'from_': 'from'
		}

class GrafanaQueryTarget(BaseModel): #  pylint: disable=too-few-public-methods
	type: str
	target: str
	refId: str

class GrafanaQuery(BaseModel): #  pylint: disable=too-few-public-methods
	app: str
	range: GrafanaQueryTargetRange
	intervalMs: int
	timezone: str
	targets: List[GrafanaQueryTarget]

@grafana_metrics_router.get('/query')
@grafana_metrics_router.post('/query')
async def grafana_query(query: GrafanaQuery): #  pylint: disable=too-many-locals,too-many-branches,too-many-statements
	logger.trace("Grafana query: %s", query)
	results = []
	redis = await get_redis_client()
	for target in query.targets:
		# UTC time values
		from_time = int((datetime.strptime(query.range.from_, "%Y-%m-%dT%H:%M:%S.%fZ") - datetime(1970, 1, 1)).total_seconds() * 1000)
		to_time = int((datetime.strptime(query.range.to, "%Y-%m-%dT%H:%M:%S.%fZ") - datetime(1970, 1, 1)).total_seconds() * 1000)
		time_bucket = int(query.intervalMs/1000)
		if time_bucket <= 0:
			time_bucket = 1
		if target.type == "timeserie":
			res = {
				"target": target.target,
				"datapoints": []
			}
			try:
				metric = metrics_registry.get_metric_by_name(target.target)
				metric_vars = metric.get_vars_by_name(target.target)
			except Exception: #  pylint: disable=broad-except
				try:
					metric = metrics_registry.get_metric_by_redis_key(target.target)
					metric_vars = metric.get_vars_by_redis_key(target.target)
				except Exception as err: #  pylint: disable=broad-except
					logger.debug(err)
					continue

			redis_key = metric.get_redis_key(**metric_vars)
			retention_time = metric.retention
			redis_key_extension = None

			if metric.downsampling:
				downsampling = sorted(metric.downsampling, key = lambda x: x[1])
				if not (to_time - from_time) <= retention_time:
					for time_frame in downsampling:
						if (to_time - from_time) <= time_frame[1]:
							redis_key_extension = time_frame[0]
							retention_time = time_frame[1]
							time_bucket = get_time_bucket(redis_key_extension)
							break

				time_min = round(time.time() * 1000) - retention_time
				if (from_time - time_min + 5000)  < 0:
					for time_frame in downsampling:
						redis_key_extension = time_frame[0]
						retention_time = time_frame[1]
						time_bucket = get_time_bucket(redis_key_extension)
						time_min = round(time.time() * 1000) - retention_time
						if (from_time - time_min + 5000)  >= 0:
							break
					logger.warning("Data out of range. Using next higher time bucket (%s).", redis_key_extension)

			if redis_key_extension:
				redis_key = f"{redis_key}:{redis_key_extension}"

			cmd = ["TS.RANGE", redis_key, from_time, to_time, "AGGREGATION", "avg", time_bucket]
			try:
				rows = await redis.execute_command(*cmd)
			except aredis.exceptions.ResponseError as exc:
				logger.debug("%s %s", cmd, exc)
				rows = []

			def align_timestamp(timestamp):
				"""Align timestamp to 5 second intervals, needed for stacking in grafana"""
				return 5000*round(int(timestamp)/5000)

			if metric.time_related and metric.aggregation == "sum":
				# Time series data is stored aggregated in 5 second intervals
				res["datapoints"] = [ [float(r[1])/5.0, align_timestamp(r[0])] for r in rows ]
			else:
				res["datapoints"] = [ [float(r[1]) if b'.' in r[1] else int(r[1]), align_timestamp(r[0])] for r in rows ]
			logger.trace("Grafana query result: %s", res)
			results.append(res)
	return results
