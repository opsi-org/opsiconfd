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

import copy
import aredis
import aiohttp
from datetime import datetime
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Dict, List
from operator import itemgetter
from urllib.parse import urlparse

from ..logging import logger
from ..config import config
from ..server import get_external_url, get_internal_url
from ..worker import get_redis_client
from ..statistics import metrics_registry, GRAFANA_DATASOURCE_TEMPLATE, GRAFANA_DASHBOARD_TEMPLATE

grafana_metrics_router = APIRouter()

def metrics_setup(app):
	app.include_router(grafana_metrics_router, prefix="/metrics/grafana")


"""
async def create_api_key():
	api_key = None
	if not api_key:
		auth = aiohttp.BasicAuth("adminuser", "adminuser")
		async with aiohttp.ClientSession(auth=auth) as session:
			resp = await session.get(f"{config.grafana_internal_url}/api/auth/keys")
			for key in await resp.json():
				if key["name"] == "opsiconfd":
					await session.delete(f"{config.grafana_internal_url}/api/auth/keys/{key['id']}")
			json = {"name": "opsiconfd", "role":"Admin", "secondsToLive": None}
			resp = await session.post(f"{config.grafana_internal_url}/api/auth/keys", json=json)
			api_key = (await resp.json())["key"]
"""

@grafana_metrics_router.get("/dashboard")
async def grafana_index(request: Request):
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
	
	async with aiohttp.ClientSession(auth=auth) as session:
		json = GRAFANA_DATASOURCE_TEMPLATE
		json["url"] = f"{get_internal_url()}/metrics/grafana/"
		resp = await session.get(f"{url.scheme}://{url.netloc}/api/datasources/name/{json['name']}")
		if resp.status == 200:
			_id = (await resp.json())["id"]
			resp = await session.put(f"{url.scheme}://{url.netloc}/api/datasources/{_id}", json=json)
		else:
			resp = await session.post(f"{url.scheme}://{url.netloc}/api/datasources", json=json)
		
		if resp.status == 200:
			json = {
				"folderId": 0,
				"overwrite": True,
				"dashboard": await grafana_dashboard_config()
			}
			resp = await session.post(f"{url.scheme}://{url.netloc}/api/dashboards/db", json=json)
		else:
			logger.error("Failed to create grafana datasource: %s - %s", resp.status, await resp.text())
	return RedirectResponse(url=f"{config.grafana_external_url}/d/opsiconfd_main/opsiconfd-main-dashboard?refresh=5s&kiosk=tv")

@grafana_metrics_router.get('/dashboard/config')
async def grafana_dashboard_config():
	redis = await get_redis_client()
	workers = []
	async for redis_key in redis.scan_iter(f"opsiconfd:worker_registry:*"):
		redis_key = redis_key.decode("utf-8")
		workers.append({"node_name": redis_key.split(':')[-2], "worker_num": int(redis_key.split(':')[-1])})
	workers.sort(key=itemgetter("node_name", "worker_num"))

	clients = []
	async for redis_key in redis.scan_iter(f"opsiconfd:stats:client:num_http_request:*"):
		redis_key = redis_key.decode("utf-8")
		clients.append({"client_addr": redis_key.split(':')[-1]})
	clients.sort(key=itemgetter("client_addr"))

	dashboard = copy.deepcopy(GRAFANA_DASHBOARD_TEMPLATE)
	panels = []
	x = 0
	y = 0
	for panel_id, metric in enumerate(metrics_registry.get_metrics()):
		if not metric.grafana_config:
			continue
		panel_id += 1
		panel = metric.grafana_config.get_panel(id=panel_id, x=x, y=y)
		if metric.scope == "worker":
			for i, worker in enumerate(workers):
				panel["targets"].append({
					"refId": chr(65+i),
					"target": metric.get_name(node_name=worker["node_name"], worker_num=worker["worker_num"]),
					"type": "timeserie"
				})
		elif metric.scope == "client":
			for i, client in enumerate(clients):
				panel["targets"].append({
					"refId": chr(65+i),
					"target": metric.get_name(client_addr=client["client_addr"]),
					"type": "timeserie"
				})
		panels.append(panel)
		x += panel["gridPos"]["w"]
		if x >= 24:
			x = 0
			y += panel["gridPos"]["h"]
	
	dashboard["panels"] = panels
	return dashboard

@grafana_metrics_router.get('/?')
async def grafana_index():
	# should return 200 ok. Used for "Test connection" on the datasource config page.
	return None

@grafana_metrics_router.get('/search')
@grafana_metrics_router.post('/search')
async def grafana_search():
	redis = await get_redis_client()
	
	names = []
	for metric in metrics_registry.get_metrics():
		if metric.scope == "worker":
			workers = []
			async for redis_key in redis.scan_iter(f"opsiconfd:worker_registry:*"):
				redis_key = redis_key.decode("utf-8")
				workers.append({"node_name": redis_key.split(':')[-2], "worker_num": int(redis_key.split(':')[-1])})
			workers.sort(key=itemgetter("node_name", "worker_num"))
			for worker in workers:
				names.append(metric.get_name(**worker))
		elif metric.scope == "client":
			clients = []
			async for redis_key in redis.scan_iter(f"opsiconfd:stats:client:num_http_request:*"):
				redis_key = redis_key.decode("utf-8")
				clients.append({"client_addr": redis_key.split(':')[-1]})
				logger.error(redis_key)
			for client in clients:
				names.append(metric.get_name(**client))
		else:
			names.append(metric.get_name())
	return sorted(names)

class GrafanaQueryTargetRange(BaseModel):
	from_: str
	to: str
	raw: dict
	class Config:
		fields = {
			'from_': 'from'
		}

class GrafanaQueryTarget(BaseModel):
	type: str
	target: str
	refId: str

class GrafanaQuery(BaseModel):
	app: str
	range: GrafanaQueryTargetRange
	intervalMs: int
	targets: List[GrafanaQueryTarget]

@grafana_metrics_router.get('/query')
@grafana_metrics_router.post('/query')
async def grafana_query(query: GrafanaQuery):
	logger.debug("Grafana query: %s", query)
	results = []
	redis = await get_redis_client()
	for target in query.targets:
		from_ = datetime.strptime(query.range.from_, "%Y-%m-%dT%H:%M:%S.%fZ")
		to = datetime.strptime(query.range.to, "%Y-%m-%dT%H:%M:%S.%fZ")
		time_bucket = int(query.intervalMs/1000)
		if (time_bucket <= 0):
			time_bucket = 1
		if target.type == "timeserie":
			res = {
				"target": target.target,
				"datapoints": []
			}
			try:
				metric = metrics_registry.get_metric_by_name(target.target)
				vars = metric.get_vars_by_name(target.target)
			except Exception:
				try:
					metric = metrics_registry.get_metric_by_redis_key(target.target)
					vars = metric.get_vars_by_redis_key(target.target)
				except Exception as exc:
					logger.debug(exc)
					#results.append(res)
					continue
			
			cmd = ["TS.RANGE", metric.get_redis_key(**vars), int(from_.timestamp()*1000), int(to.timestamp()*1000), "AGGREGATION", "avg", time_bucket]
			try:
				#rows = await redis.execute_command(" ".join([ str(x) for x in cmd ]))
				rows = await redis.execute_command(*cmd)
			except aredis.exceptions.ResponseError as exc:
				logger.debug("%s %s", cmd, exc)
				rows = []
			# [ [value1, timestamp1], [value2, timestamp2] ]
			res["datapoints"] = [ [float(r[1]) if b'.' in r[1] else int(r[1]), r[0]] for r in rows ]
			
			#########logger.essential("Grafana query result: %s", target.target)
			#print(target.target)
			#if target.target.find("Duration of RPCs") != -1:
			#	print(res)
			results.append(res)
	return results
