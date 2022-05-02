# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
metrics
"""

import copy
import ssl
from datetime import datetime
from operator import itemgetter
from typing import List, Union
from urllib.parse import urlparse

import aiohttp
import aioredis
from fastapi import APIRouter
from fastapi.responses import RedirectResponse
from pydantic import BaseModel  # pylint: disable=no-name-in-module

from ..config import config
from ..grafana import GRAFANA_DASHBOARD_TEMPLATE, GRAFANA_DATASOURCE_TEMPLATE
from ..logging import logger
from ..statistics import get_time_bucket_duration, metrics_registry
from ..utils import async_redis_client, ip_address_from_redis_key

grafana_metrics_router = APIRouter()


def metrics_setup(app):
	app.include_router(grafana_metrics_router, prefix="/metrics/grafana")


async def get_workers():
	redis = await async_redis_client()
	workers = []
	async for redis_key in redis.scan_iter("opsiconfd:worker_registry:*"):
		redis_key = redis_key.decode("utf-8")
		workers.append({"node_name": redis_key.split(":")[-2], "worker_num": int(redis_key.split(":")[-1])})
	workers.sort(key=itemgetter("node_name", "worker_num"))
	return workers


async def get_nodes():
	return {worker["node_name"] for worker in await get_workers()}


async def get_clients(metric_id):
	redis = await async_redis_client()
	clients = []
	async for redis_key in redis.scan_iter(f"opsiconfd:stats:{metric_id}:*"):
		redis_key = redis_key.decode("utf-8")
		clients.append({"client_addr": ip_address_from_redis_key(redis_key.split(":")[-1])})
	clients.sort(key=itemgetter("client_addr"))
	return clients


@grafana_metrics_router.get("/")
async def grafana_index():
	# should return 200 ok. Used for "Test connection" on the datasource config page.
	return None


@grafana_metrics_router.get("/dashboard")
async def grafana_dashboard():
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
	ssl_context: Union[ssl.SSLContext, bool] = ssl.create_default_context(cafile=config.ssl_trusted_certs)
	if not config.grafana_verify_cert:
		ssl_context = False
	async with aiohttp.ClientSession(auth=auth, headers=headers) as session:
		json = GRAFANA_DATASOURCE_TEMPLATE
		json["url"] = f"{config.grafana_data_source_url}/metrics/grafana/"
		resp = await session.get(f"{base_url}/api/datasources/name/{json['name']}", ssl=ssl_context)
		if resp.status == 200:
			_id = (await resp.json())["id"]
			resp = await session.put(f"{base_url}/api/datasources/{_id}", json=json, ssl=ssl_context)
		else:
			resp = await session.post(f"{base_url}/api/datasources", json=json, ssl=ssl_context)

		if resp.status == 200:
			json = {"folderId": 0, "overwrite": True, "dashboard": await grafana_dashboard_config()}
			resp = await session.post(f"{base_url}/api/dashboards/db", json=json, ssl=ssl_context)
		else:
			logger.error("Failed to create grafana datasource: %s - %s", resp.status, await resp.text())
	return RedirectResponse(url=f"{config.grafana_external_url}/d/opsiconfd_main/opsiconfd-main-dashboard?kiosk=tv")


@grafana_metrics_router.get("/dashboard/config")
async def grafana_dashboard_config():  # pylint: disable=too-many-locals
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
		panel = metric.grafana_config.get_panel(panel_id=panel_id, pos_x=pos_x, pos_y=pos_y)
		if metric.subject == "worker":
			for i, worker in enumerate(workers):  # pylint: disable=use-list-copy
				panel["targets"].append(
					{
						"refId": chr(65 + i),
						"target": metric.get_name(node_name=worker["node_name"], worker_num=worker["worker_num"]),
						"type": "timeserie",
					}
				)
		elif metric.subject == "node":
			for i, node_name in enumerate(nodes):  # pylint: disable=use-list-copy
				panel["targets"].append({"refId": chr(65 + i), "target": metric.get_name(node_name=node_name), "type": "timeserie"})
		elif metric.subject == "client":
			for i, client in enumerate(clients):  # pylint: disable=use-list-copy
				panel["targets"].append(
					{"refId": chr(65 + i), "target": metric.get_name(client_addr=client["client_addr"]), "type": "timeserie"}
				)
		panels.append(panel)
		pos_x += panel["gridPos"]["w"]
		if pos_x >= 24:
			pos_x = 0
			pos_y += panel["gridPos"]["h"]

	dashboard["panels"] = panels
	return dashboard


@grafana_metrics_router.get("/search")
@grafana_metrics_router.post("/search")
async def grafana_search():
	workers = await get_workers()
	nodes = await get_nodes()
	clients = await get_clients("client:sum_http_request_number")

	names = []
	for metric in metrics_registry.get_metrics():
		if metric.subject == "worker":
			names += [metric.get_name(**worker) for worker in workers]  # pylint: disable=loop-invariant-statement
		elif metric.subject == "node":
			names += [metric.get_name(node_name=node_name) for node_name in nodes]  # pylint: disable=loop-invariant-statement
		elif metric.subject == "client":
			names += [metric.get_name(**client) for client in clients]  # pylint: disable=loop-invariant-statement
		else:
			names.append(metric.get_name())
	return sorted(names)


class GrafanaQueryTargetRange(BaseModel):  # pylint: disable=too-few-public-methods
	from_: str
	to: str
	raw: dict

	class Config:  # pylint: disable=too-few-public-methods
		fields = {"from_": "from"}


class GrafanaQueryTarget(BaseModel):  # pylint: disable=too-few-public-methods
	type: str
	target: str
	refId: str


class GrafanaQuery(BaseModel):  # pylint: disable=too-few-public-methods
	app: str
	range: GrafanaQueryTargetRange
	intervalMs: int
	timezone: str
	targets: List[GrafanaQueryTarget]


def align_timestamp(timestamp):
	"""Align timestamp to 5 second intervals, needed for stacking in grafana"""
	return 5000 * round(int(timestamp) / 5000)


@grafana_metrics_router.get("/query")
@grafana_metrics_router.post("/query")
async def grafana_query(query: GrafanaQuery):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	logger.trace("Grafana query: %s", query)
	results = []
	redis = await async_redis_client()

	# Unix timestamp (UTC) in milliseconds
	from_ms = int(datetime.fromisoformat(query.range.from_.replace("Z", "+00:00")).timestamp()) * 1000
	to_ms = int(datetime.fromisoformat(query.range.to.replace("Z", "+00:00")).timestamp()) * 1000
	time_range_ms = to_ms - from_ms
	query_bucket_duration_ms = max(1000, round(query.intervalMs))

	for target in query.targets:
		if target.type != "timeserie":
			logger.warning("Unhandled target type: %s", target.type)
			continue

		bucket_duration_ms = query_bucket_duration_ms

		try:  # pylint: disable=loop-try-except-usage
			metric = metrics_registry.get_metric_by_name(target.target)
			metric_vars = metric.get_vars_by_name(target.target)
		except ValueError:
			try:  # pylint: disable=loop-try-except-usage
				metric = metrics_registry.get_metric_by_redis_key(target.target)
				metric_vars = metric.get_vars_by_redis_key(target.target)
			except ValueError as err:
				logger.debug(err)
				continue

		redis_key = metric.get_redis_key(**metric_vars)
		redis_key_extension = None
		ts_max_interval_ms = metric.retention

		if time_range_ms > ts_max_interval_ms and metric.downsampling:
			# Requested time range is bigger than the metric retention time
			# Get the best matching downsampling rule
			# downsampling: [<ts_key_extension>, <retention_time_in_ms>, <aggregation>]
			# e.g. ["minute", 24 * 3600 * 1000, "avg"]
			downsampling = sorted(metric.downsampling, key=lambda dsr: dsr[1])
			for ds_rule in downsampling:
				if time_range_ms <= ds_rule[1]:
					redis_key_extension = ds_rule[0]
					ts_max_interval_ms = ds_rule[1]
					break

		if redis_key_extension:
			bucket_duration_ms = get_time_bucket_duration(redis_key_extension)
			redis_key = f"{redis_key}:{redis_key_extension}"

		# https://redis.io/commands/ts.range/
		# Aggregate results into time buckets, duration of each bucket in milliseconds is bucket_duration_ms
		cmd = ("TS.RANGE", redis_key, from_ms, to_ms, "AGGREGATION", "avg", bucket_duration_ms)
		try:  # pylint: disable=loop-try-except-usage
			rows = await redis.execute_command(*cmd)
		except aioredis.ResponseError as err:  # pylint: disable=dotted-import-in-loop
			logger.warning("%s %s", cmd, err)
			rows = []  # pylint: disable=use-tuple-over-list

		res = {"target": target.target, "datapoints": []}
		if metric.time_related and metric.aggregation == "sum":
			# Time series data is stored aggregated in 5 second intervals
			res["datapoints"] = [[float(r[1]) / 5.0, align_timestamp(r[0])] for r in rows]  # type: ignore[misc] # pylint: disable=loop-invariant-statement
		else:
			res["datapoints"] = [[float(r[1]), align_timestamp(r[0])] for r in rows]  # type: ignore[misc] # pylint: disable=loop-invariant-statement
		logger.trace("Grafana query result: %s", res)
		results.append(res)
	return results
