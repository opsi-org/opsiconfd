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

import time
import socket
import lz4.frame
import gzip
import zlib
import traceback
import urllib.parse
import orjson
import asyncio
import datetime
import contextvars
contextvar_client_address = contextvars.ContextVar("client_address", default=None)

from fastapi import HTTPException, APIRouter
from fastapi.requests import Request
from fastapi.responses import Response, ORJSONResponse

from OPSI.Util import serialize, deserialize

from ..logging import logger
from ..backend import get_client_backend, get_backend_interface
from ..worker import run_in_threadpool, get_node_name, get_worker_num, get_metrics_collector, contextvar_request_id, get_redis_client
from ..statistics import metrics_registry, Metric, GrafanaPanelConfig


# https://fastapi.tiangolo.com/tutorial/bigger-applications/
jsonrpc_router = APIRouter()

#context_jsonrpc_call_id = ContextVar("jsonrpc_call_id")
####context_request_id: ContextVar[int] = ContextVar("request_id")

'''
@jsonrpc_api.exception_handler(Exception)
async def exception_handler(request: Request, exception: Exception):
	print("==============================exception_handler=====================================")
	#return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
	#return Response(content=str(exception), status_code=500, media_type='application/json')
	#return JSONResponse(content={'error': str(exception)}, status_code=500)
	return JSONResponse(content={'error': str(exception)}, status_code=200)
'''

metrics_registry.register(
	Metric(
		id="worker:avg_rpc_number",
		name="Average RPCs processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Remote procedure calls", units=["short"], decimals=0, stack=True, yaxis_min = 0),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	),
	Metric(
		id="worker:avg_rpc_duration",
		name="Average duration of RPCs processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		zero_if_missing=False,
		subject="worker",
		server_timing_header_factor=1000,
		grafana_config=GrafanaPanelConfig(type="heatmap", title="Duration of remote procedure calls", units=["s"], decimals=0),
		downsampling=[["minute", 24 * 3600 * 1000], ["hour", 60 * 24 * 3600 * 1000], ["day", 4 * 365 * 24 * 3600 * 1000]]
	)
)

xid = 0

def jsonrpc_setup(app):
	app.include_router(jsonrpc_router, prefix="/rpc")


async def store_rpc(redis_client, data, max_rpcs=9999):
	pipe = await redis_client.pipeline()
	await pipe.lpush("opsiconfd:stats:rpcs", orjson.dumps(data))
	await pipe.ltrim("opsiconfd:stats:rpcs", 0, max_rpcs)
	await pipe.execute()

# Some clients are using /rpc/rpc
@jsonrpc_router.get(".*")
@jsonrpc_router.post(".*")
async def process_jsonrpc(request: Request, response: Response):
	results = []
	try:
		global xid
		xid += 1
		myid = xid
		#print("=====", contextvar_request_id.get())
		#backend = await asyncio.get_event_loop().run_in_executor(None, lambda: get_backend(request))
		#backend = await run_in_threadpool(get_backend)
		backend = get_client_backend()
		body = await request.body()
		jsonrpc = None
		if body:
			jsonrpc = body
			content_type = request.headers.get("content-type", "")
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
			
			# workaround for "JSONDecodeError: str is not valid UTF-8: surrogates not allowed".
			# opsi-script produces invalid UTF-8.
			# Therefore we do not pass bytes to orjson.loads but
			# decoding with "replace" first and passing unicode to orjson.loads.
			# See orjson documentation for details.
			jsonrpc = await run_in_threadpool(jsonrpc.decode, "utf-8", "replace")
		else:
			jsonrpc = urllib.parse.unquote(request.url.query)
		logger.trace("jsonrpc: %s", jsonrpc)
		jsonrpc = await run_in_threadpool(orjson.loads, jsonrpc)
		if not type(jsonrpc) is list:
			jsonrpc = [jsonrpc]
		tasks = []
		for rpc in jsonrpc:
			task = run_in_threadpool(process_rpc, request, response, rpc, backend)
			tasks.append(task)
		asyncio.get_event_loop().create_task(
			get_metrics_collector().add_value("worker:avg_rpc_number", len(jsonrpc), {"node_name": get_node_name(), "worker_num": get_worker_num()})
		)
		#context_jsonrpc_call_id.set(myid)
		#print(f"start {myid}")
		for result in await asyncio.gather(*tasks):
			results.append(result[0])
			asyncio.get_event_loop().create_task(
				get_metrics_collector().add_value("worker:avg_rpc_duration", result[1], {"node_name": get_node_name(), "worker_num": get_worker_num()})
			)
			redis_client = await get_redis_client()
			rpc_count = await redis_client.incr("opsiconfd:stats:num_rpcs")
			error = bool(result[0].get("error"))
			date = result[0].get("date")
			params = [param for param in result[0].get("params", []) if param]
			logger.trace("RPC Count: %s", rpc_count)			
			logger.trace("params: %s", params)
			num_results = 0
			if result[0].get("result"):
				num_results = 1
				if isinstance(result[0].get("result"), list):
					num_results = len(result[0].get("result"))
			logger.debug("num_results: %s", num_results)

			data = {
				"rpc_num": rpc_count,
				"method": result[0].get('method'),
				"num_params": len(params),
				"date": date,
				"client": request.client.host,
				"error": error,
				"num_results": num_results,
				"duration": result[1]
			}

			asyncio.get_event_loop().create_task(store_rpc(redis_client, data))
			response.status_code = 200
	except HTTPException as e:
		logger.error(e)
		raise
	except Exception as e:
		logger.error(e, exc_info=True)
		tb = traceback.format_exc()
		error = {
			"message": str(e),
			"class": e.__class__.__name__,
			# TODO: config
			"details": None # str(tb) 
		}
		response.status_code = 400
		results = [{"jsonrpc": "2.0", "id": None, "result": None, "error": error}]
	
	data = await run_in_threadpool(orjson.dumps, results[0] if len(results) == 1 else results)
	response.headers["content-type"] = "application/json"
	
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

	response.body = data
	return response

def process_rpc(request: Request, response: Response, rpc, backend):
	rpc_id = None
	try:
		
		start = time.perf_counter()
		rpc_call_time = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
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
					raise TypeError(u"kwargs param is not a dict: %r" % params[-1])

				for (key, value) in kwargs.items():
					keywords[str(key)] = deserialize(value)
		params = deserialize(params)
		
		result = None
		method = getattr(backend, method_name)
		if method_name != "backend_exit":
			if method_name == "getDomain":
				try:
					client_address = contextvar_client_address.get()
					if not client_address:
						raise ValueError("Failed to get client address")
					result = ".".join(socket.gethostbyaddr(client_address)[0].split(".")[1:])
				except Exception as e:
					logger.debug("Failed to get domain by client address: %s", e)
			if result is None:
				if keywords:
					result = method(*params, **keywords)
				else:
					result = method(*params)
		params.append(keywords)
		response = {"jsonrpc": "2.0", "id": rpc_id, "method": method_name, "params": params, "result": result, "date": rpc_call_time, "client": request.client.host, "error": None}
		response = serialize(response)

		end = time.perf_counter()

		logger.info("Backend execution of method '%s' took %0.4f seconds", method_name, end - start)
		logger.debug("Sending result (len: %d)", len(str(response)))
		logger.trace(response)

		return [response, end - start]
	except Exception as e:
		logger.error(e, exc_info=True)
		tb = traceback.format_exc()
		error = {"message": str(e), "class": e.__class__.__name__}
		# TODO: config
		if True:
			error["details"] = str(tb)
		return [{"jsonrpc": "2.0", "id": rpc_id, "method": method_name, "params": params, "result": None, "date": rpc_call_time, "client": request.client.host,  "error": error}, 0]
		
