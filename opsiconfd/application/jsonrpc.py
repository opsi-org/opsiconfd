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

import asyncio
import datetime
import time
import socket
import traceback
import urllib.parse
import gzip
import zlib
import lz4.frame
import orjson
import msgpack

from fastapi import HTTPException, APIRouter
from fastapi.requests import Request
from fastapi.responses import Response

from OPSI.Util import serialize, deserialize

from ..logging import logger
from ..backend import get_client_backend, get_backend_interface, get_backend, opsiconfd_backend
from ..worker import (
	run_in_threadpool, get_metrics_collector, get_redis_client, sync_redis_client,
	contextvar_client_address, contextvar_client_session
)
from ..statistics import metrics_registry, Metric, GrafanaPanelConfig
from ..utils import decode_redis_result, get_node_name, get_worker_num

# time in seconds
EXPIRE = (60*60*24)
EXPIRE_UPTODATE = (60*60*24)
CALL_TIME_TO_CACHE = 0.5

PRODUCT_METHODS = [
	"createProduct",
	"createNetBootProduct",
	"createLocalBootProduct",
	"createProductDependency",
	"deleteProductDependency",
	"product_delete",
	"product_deleteObjects",
	"product_createObjects",
	"product_insertObject",
	"product_updateObject",
	"product_updateObjects",
	"productDependency_create",
	"productDependency_createObjects",
	"productDependency_delete",
	"productDependency_deleteObjects",
	"productOnDepot_delete",
	"productOnDepot_create",
	"productOnDepot_deleteObjects",
	"productOnDepot_createObjects",
	"productOnDepot_insertObject",
	"productOnDepot_updateObject",
	"productOnDepot_updateObjects"
]

jsonrpc_router = APIRouter()

metrics_registry.register(
	Metric(
		id="worker:sum_jsonrpc_number",
		name="Average RPCs processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		aggregation="sum",
		zero_if_missing="continuous",
		time_related=True,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="JSONRPCs/s", units=["short"], decimals=0, stack=True, yaxis_min=0),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_jsonrpc_duration",
		name="Average duration of RPCs processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		aggregation="avg",
		zero_if_missing="one",
		subject="worker",
		server_timing_header_factor=1000,
		grafana_config=GrafanaPanelConfig(type="heatmap", title="JSONRPC duration", units=["s"], decimals=0),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	)
)

def jsonrpc_setup(app):
	app.include_router(jsonrpc_router, prefix="/rpc")


def _store_rpc(data, max_rpcs=9999):
	try:
		with sync_redis_client() as redis:
			pipe = redis.pipeline()
			pipe.lpush("opsiconfd:stats:rpcs", msgpack.dumps(data))  # pylint: disable=c-extension-no-member
			pipe.ltrim("opsiconfd:stats:rpcs", 0, max_rpcs)
			pipe.execute()
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)

def _get_sort_algorithm(params):
	algorithm = None
	if len(params) > 1:
		algorithm = params[1]
	if algorithm not in ("algorithm1", "algorithm2"):
		algorithm = "algorithm1"
		try:
			backend = get_client_backend()
			default = backend.config_getObjects(id="product_sort_algorithm")[0].getDefaultValues()  # pylint: disable=no-member
			if "algorithm2" in default:
				algorithm = "algorithm2"
		except IndexError:
			pass
	return algorithm

def _store_product_ordering(result, params):
	try:
		if len(params) < 1:
			logger.warning("Could not store product ordering in redis cache. No 'depot_id' given.")
			return
		if len(params) > 1:
			algorithm = _get_sort_algorithm(params)
		else:
			algorithm = "algorithm1"
		with sync_redis_client() as redis:
			with redis.pipeline() as pipe:
				pipe.unlink(f"opsiconfd:jsonrpccache:{params[0]}:products")
				pipe.unlink(f"opsiconfd:jsonrpccache:{params[0]}:products:{algorithm}")
				for val in result.get("not_sorted"):
					pipe.zadd(f"opsiconfd:jsonrpccache:{params[0]}:products", {val: 1})
				pipe.expire(f"opsiconfd:jsonrpccache:{params[0]}:products", EXPIRE)
				for idx, val in enumerate(result.get("sorted")):
					pipe.zadd(f"opsiconfd:jsonrpccache:{params[0]}:products:{algorithm}", {val: idx})
				pipe.expire(f"opsiconfd:jsonrpccache:{params[0]}:products:{algorithm}", EXPIRE)
				now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
				pipe.set(f"opsiconfd:jsonrpccache:{params[0]}:products:uptodate", now)
				pipe.set(f"opsiconfd:jsonrpccache:{params[0]}:products:{algorithm}:uptodate", now)
				pipe.expire(f"opsiconfd:jsonrpccache:{params[0]}:products:uptodate", EXPIRE_UPTODATE)
				pipe.expire(f"opsiconfd:jsonrpccache:{params[0]}:products:{algorithm}:uptodate", EXPIRE_UPTODATE)
				pipe.sadd("opsiconfd:jsonrpccache:depots", params[0])

				pipe.execute()
	except Exception as err: # pylint: disable=broad-except
		logger.error(err, exc_info=True)

def _set_jsonrpc_cache_outdated(params):
	with sync_redis_client() as redis:
		saved_depots = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
		depots = []
		for depot in saved_depots:
			if str(params).find(depot) != -1:
				depots.append(depot)
		if len(depots) == 0:
			depots = saved_depots

		with redis.pipeline() as pipe:
			for depot in depots:
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:uptodate")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm1:uptodate")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm2:uptodate")
			pipe.execute()

def _remove_depot_from_jsonrpc_cache(depot_id):
	with sync_redis_client() as redis:
		with redis.pipeline() as pipe:
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products")
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:uptodate")
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1")
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1:uptodate")
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm2")
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm2:uptodate")
			pipe.srem("opsiconfd:jsonrpccache:depots", depot_id)
			pipe.execute()

# Some clients are using /rpc/rpc
@jsonrpc_router.get(".*")
@jsonrpc_router.post(".*")
async def process_jsonrpc(request: Request, response: Response):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	results = []
	content_type = None
	try:
		backend = get_client_backend()
		body = await request.body()
		jsonrpc = None
		content_type = request.headers.get("content-type")
		if body:
			jsonrpc = body
			content_encoding = request.headers.get("content-encoding", "")
			logger.debug("Content-Type: %s, Content-Encoding: %s", content_type, content_encoding)

			compression = None
			if "lz4" in content_encoding:
				compression = "lz4"
			elif "deflate" in content_encoding:
				compression = "deflate"
			elif "gzip" in content_encoding:
				compression = "gzip"
			if compression:
				data_len = len(jsonrpc)
				decomp_start = time.perf_counter()
				if "lz4" in content_encoding:
					jsonrpc = await run_in_threadpool(lz4.frame.decompress, jsonrpc)
				elif "deflate" in content_encoding:
					jsonrpc = await run_in_threadpool(zlib.decompress, jsonrpc)
				elif "gzip" in content_encoding:
					jsonrpc = await run_in_threadpool(gzip.decompress, jsonrpc)
				logger.debug(
					"%s decompression ratio: %d => %d = %0.2f%%, time: %0.2fms",
					compression, data_len, len(jsonrpc), 100 - 100 * (data_len / len(jsonrpc)),
					1000 * (time.perf_counter() - decomp_start)
				)

			if content_type != "application/msgpack":
				# workaround for "JSONDecodeError: str is not valid UTF-8: surrogates not allowed".
				# opsi-script produces invalid UTF-8.
				# Therefore we do not pass bytes to orjson.loads but
				# decoding with "replace" first and passing unicode to orjson.loads.
				# See orjson documentation for details.
				jsonrpc = await run_in_threadpool(jsonrpc.decode, "utf-8", "replace")
		else:
			jsonrpc = urllib.parse.unquote(request.url.query)
			if content_type == "application/msgpack":
				jsonrpc = await run_in_threadpool(jsonrpc.encode, "ascii")

		logger.trace("jsonrpc: %s", jsonrpc)

		decode_start = time.perf_counter()
		if content_type == "application/msgpack":
			jsonrpc = await run_in_threadpool(msgpack.loads, jsonrpc)
			logger.debug("Decode msgpack time: %0.2fms", 1000 * (time.perf_counter() - decode_start))
		else:
			jsonrpc = await run_in_threadpool(orjson.loads, jsonrpc)  # pylint: disable=c-extension-no-member
			logger.debug("Decode json time: %0.2fms", 1000 * (time.perf_counter() - decode_start))

		if not isinstance(jsonrpc, list):
			jsonrpc = [jsonrpc]
		tasks = []

		for rpc in jsonrpc:
			task = None
			if rpc.get('method') in PRODUCT_METHODS:
				asyncio.get_event_loop().create_task(
					run_in_threadpool(_set_jsonrpc_cache_outdated, rpc.get('params'))
				)
			elif rpc.get('method') in ("deleteDepot", "host_delete"):
				asyncio.get_event_loop().create_task(
					run_in_threadpool(_remove_depot_from_jsonrpc_cache, rpc.get('params')[0])
				)
			elif rpc.get('method') == "getProductOrdering":
				depot = rpc.get('params')[0]
				cache_outdated = backend.config_getIdents(id=f"opsiconfd.{depot}.product.cache.outdated")  # pylint: disable=no-member
				algorithm = _get_sort_algorithm(rpc.get('params'))
				redis_client = await get_redis_client()
				if cache_outdated:
					get_backend().config_delete(id=f"opsiconfd.{depot}.product.cache.outdated")  # pylint: disable=no-member
					await redis_client.unlink(f"opsiconfd:jsonrpccache:{depot}:products:uptodate")
					await redis_client.unlink(f"opsiconfd:jsonrpccache:{depot}:products:algorithm1:uptodate")
					await redis_client.unlink(f"opsiconfd:jsonrpccache:{depot}:products:algorithm2:uptodate")
				else:
					products_uptodate = await redis_client.get(f"opsiconfd:jsonrpccache:{depot}:products:uptodate")
					sorted_uptodate = await redis_client.get(f"opsiconfd:jsonrpccache:{depot}:products:{algorithm}:uptodate")
					if products_uptodate and sorted_uptodate:
						task = run_in_threadpool(read_redis_cache, request, response, rpc)

			if not task:
				task = run_in_threadpool(process_rpc, request, response, rpc, backend)
			tasks.append(task)

		asyncio.get_event_loop().create_task(
			get_metrics_collector().add_value(
				"worker:sum_jsonrpc_number",
				len(jsonrpc),
				{"node_name": get_node_name(), "worker_num": get_worker_num()}
			)
		)

		for result in await asyncio.gather(*tasks):
			results.append(result[0])
			asyncio.get_event_loop().create_task(
				get_metrics_collector().add_value(
					"worker:avg_jsonrpc_duration",
					result[1], {"node_name": get_node_name(), "worker_num": get_worker_num()}
				)
			)
			redis_client = await get_redis_client()
			rpc_count = await redis_client.incr("opsiconfd:stats:num_rpcs")
			error = bool(result[0].get("error"))
			date = result[2].get("date")
			params = [param for param in result[2].get("params", []) if param]
			logger.trace("RPC count: %s", rpc_count)
			logger.trace("params: %s", params)
			num_results = 0
			if result[0].get("result"):
				num_results = 1
				if isinstance(result[0].get("result"), list):
					num_results = len(result[0].get("result"))

			data = {
				"rpc_num": rpc_count,
				"method": result[2].get("method"),
				"num_params": len(params),
				"date": date,
				"client": result[2].get("client"),
				"error": error,
				"num_results": num_results,
				"duration": result[1]
			}
			logger.notice(
				"JSONRPC request: method=%s, num_params=%d, duration=%0.4f, error=%s, num_results=%d",
				data["method"], data["num_params"], data["duration"], data["error"], data["num_results"]
			)
			asyncio.get_event_loop().create_task(
				run_in_threadpool(_store_rpc, data)
			)

			if result[2].get('method') == "getProductOrdering" and result[1] > CALL_TIME_TO_CACHE:
				if result[3] == "rpc" and len(result[0].get("result").get("sorted")) > 0:
					asyncio.get_event_loop().create_task(
						run_in_threadpool(_store_product_ordering, result[0].get("result"), params)
					)

			response.status_code = 200
	except HTTPException as err: # pylint: disable=broad-except
		logger.error(err)
		raise
	except Exception as err: # pylint: disable=broad-except
		logger.error(err, exc_info=True)

		details = None
		try:
			session = contextvar_client_session.get()
			if session and session.user_store.isAdmin:
				details = str(traceback.format_exc())
		except Exception as session_err: # pylint: disable=broad-except
			logger.warning(session_err, exc_info=True)

		error = {
			"message": str(err),
			"class": err.__class__.__name__,
			"details": details
		}
		response.status_code = 400
		results = [{"jsonrpc": "2.0", "id": None, "result": None, "error": error}]

	_dumps = None
	if content_type == "application/msgpack":
		response.headers["content-type"] = "application/msgpack"
		_dumps = msgpack.dumps
	else:
		response.headers["content-type"] = "application/json"
		_dumps = orjson.dumps  # pylint: disable=c-extension-no-member
	data = await run_in_threadpool(_dumps, results[0] if len(results) == 1 else results)

	data_len = len(data)
	# TODO: config
	if data_len > 10000:
		compression = None
		accept_encoding = request.headers.get("accept-encoding", "")
		logger.debug("Accept-Encoding: %s", accept_encoding)
		if "lz4" in accept_encoding:
			compression = "lz4"
		elif "deflate" in accept_encoding:
			compression = "deflate"
		elif "gzip" in accept_encoding:
			compression = "gzip"
		if compression:
			comp_start = time.perf_counter()
			response.headers["content-encoding"] = compression
			if compression == "lz4":
				block_linked = True
				if request.headers.get("user-agent", "").startswith("opsi config editor"):
					# lz4-java - RuntimeException: Dependent block stream is unsupported (BLOCK_INDEPENDENCE must be set).
					block_linked = False
				data = await run_in_threadpool(lz4.frame.compress, data, compression_level=0, block_linked=block_linked)
			if compression == "gzip":
				data = await run_in_threadpool(gzip.compress, data)
			elif compression == "deflate":
				data = await run_in_threadpool(zlib.compress, data)
			logger.debug(
				"%s compression ratio: %d => %d = %0.2f%%, time: %0.2fms",
				compression, data_len, len(data), 100 - 100 * (len(data) / data_len),
				1000 * (time.perf_counter() - comp_start)
			)
	response.headers["content-length"] = str(len(data))
	response.body = data
	return response

def process_rpc(request: Request, response: Response, rpc, backend):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	rpc_id = None
	rpc_call_time = None
	try:
		start = time.perf_counter()
		rpc_call_time = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
		user_agent = request.headers.get('user-agent')
		method_name = rpc.get('method')
		params = rpc.get('params', [])
		rpc_id = rpc.get('id')
		logger.debug("Processing request from %s (%s) for %s", request.client.host, user_agent, method_name)
		logger.trace("Retrieved parameters %s for %s", params, method_name)

		for method in get_backend_interface():
			if method_name == method['name']:
				method_description = method
				break
		else:
			raise Exception(f"Method {method_name} not found!")

		keywords = {}
		if method_description['keywords']:
			parameter_count = 0
			if method_description['args']:
				parameter_count += len(method_description['args'])
			if method_description['varargs']:
				parameter_count += len(method_description['varargs'])

			if len(params) >= parameter_count:
				kwargs = params.pop(-1)
				if not isinstance(kwargs, dict):
					raise TypeError(f"kwargs param is not a dict: {params[-1]}")

				for (key, value) in kwargs.items():
					keywords[str(key)] = deserialize(value)
		params = deserialize(params)

		result = None
		if hasattr(opsiconfd_backend, method_name):
			result = getattr(opsiconfd_backend, method_name)(*params, **keywords)
			logger.devel(result)
		else:
			method = getattr(backend, method_name)
			if method_name != "backend_exit":
				if method_name == "getDomain":
					try:
						client_address = contextvar_client_address.get()
						if not client_address:
							raise ValueError("Failed to get client address")
						result = ".".join(socket.gethostbyaddr(client_address)[0].split(".")[1:])
					except Exception as err:  # pylint: disable=broad-except
						logger.debug("Failed to get domain by client address: %s", err)
				else:
					if keywords:
						result = method(*params, **keywords)
					else:
						result = method(*params)

		response = {"jsonrpc": "2.0", "id": rpc_id, "result": result, "error": None}
		response = serialize(response)
		rpc["date"] = rpc_call_time
		rpc["client"] = request.client.host
		end = time.perf_counter()

		logger.debug("Sending result (len: %d)", len(str(response)))
		logger.trace(response)

		return [response, end - start, rpc, "rpc"]
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		error = {"message": str(err), "class": err.__class__.__name__}
		rpc["date"] = rpc_call_time
		rpc["client"] = request.client.host
		details = None
		try:
			session = contextvar_client_session.get()
			if session and session.user_store.isAdmin:
				details = str(traceback.format_exc())
		except Exception as session_err:  # pylint: disable=broad-except
			logger.warning(session_err, exc_info=True)
		error["details"] = details
		return [{"jsonrpc": "2.0", "id": rpc_id, "result": None, "error": error}, 0, rpc, "rpc"]

def read_redis_cache(request: Request, response: Response, rpc):  # pylint: disable=too-many-locals
	now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
	try:
		start = time.perf_counter()
		depot_id = rpc.get('params')[0]
		algorithm = _get_sort_algorithm(rpc.get('params'))
		with sync_redis_client() as redis:
			with redis.pipeline() as pipe:
				pipe.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products", 0, -1)
				pipe.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products:{algorithm}", 0, -1)
				pipe.expire(f"opsiconfd:jsonrpccache:{depot_id}:products", EXPIRE)
				pipe.expire(f"opsiconfd:jsonrpccache:{depot_id}:products:{algorithm}",EXPIRE)
				pipe_results = pipe.execute()
		products = pipe_results[0]
		products_ordered = pipe_results[1]
		result = {"not_sorted": decode_redis_result(products), "sorted": decode_redis_result(products_ordered)}
		response = {
			"jsonrpc": "2.0",
			"id": rpc.get('id'),
			"result": result,
			"error": None
		}
		rpc["date"] = now
		rpc["client"] = request.client.host
		end = time.perf_counter()
		response = serialize(response)
		return [response, end - start, rpc, "redis"]
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		error = {"message": str(err), "class": err.__class__.__name__}
		rpc["date"] = now
		rpc["client"] = request.client.host
		details = None
		try:
			session = contextvar_client_session.get()
			if session and session.user_store.isAdmin:
				details = str(traceback.format_exc())
		except Exception as session_err:  # pylint: disable=broad-except
			logger.warning(session_err, exc_info=True)
		error["details"] = details
		return [{"jsonrpc": "2.0", "id": rpc.get('id'), "result": None, "error": error}, 0, rpc, "redis"]
