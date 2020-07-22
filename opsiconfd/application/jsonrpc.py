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
import gzip
import zlib
import traceback
import urllib.parse
import orjson
import asyncio
from contextvars import ContextVar

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
		id="worker:num_rpcs",
		name="RPCs processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		retention=24 * 3600 * 1000,
		subject="worker",
		grafana_config=GrafanaPanelConfig(title="Remote procedure calls", units=["short"], decimals=0, stack=True, yaxis_min = 0)
	),
	Metric(
		id="worker:rpc_duration",
		name="Duration of RPCs processed by worker {worker_num} on {node_name}",
		vars=["node_name", "worker_num"],
		aggregation="avg",
		retention=24 * 3600 * 1000,
		zero_if_missing=False,
		subject="worker",
		server_timing_header_factor=1000,
		grafana_config=GrafanaPanelConfig(type="heatmap", title="Duration of remote procedure calls", units=["s"], decimals=0)
	)
)

xid = 0

def jsonrpc_setup(app):
	app.include_router(jsonrpc_router, prefix="/rpc")


# Some clients are using /rpc/rpc
@jsonrpc_router.get(".*", response_class=ORJSONResponse)
@jsonrpc_router.post(".*", response_class=ORJSONResponse)
async def process_jsonrpc(request: Request, response: Response):
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
			if "gzip" in content_encoding:
				logger.debug("decompress gzip data")
				jsonrpc = await run_in_threadpool(gzip.decompress, jsonrpc)
			elif "deflate" in content_encoding:
				logger.debug("decompress deflate data")
				jsonrpc = await run_in_threadpool(zlib.decompress, jsonrpc)
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
		
		await get_metrics_collector().add_value("worker:num_rpcs", len(jsonrpc), {"node_name": get_node_name(), "worker_num": get_worker_num()})

		#context_jsonrpc_call_id.set(myid)
		#print(f"start {myid}")
		results = []
		for result in await asyncio.gather(*tasks):
			results.append(result[0])
			await get_metrics_collector().add_value("worker:rpc_duration", result[1], {"node_name": get_node_name(), "worker_num": get_worker_num()})
			redis_client = await get_redis_client()
			rpc_count = await redis_client.incr("opsiconfd:stats:num_rpcs")
			error = bool(result[0].get("error"))
			params = [param for param in result[0].get("params", []) if param]
			logger.trace("RPC Count: %s", rpc_count)			
			logger.trace("params: %s", params)
			num_results = 0
			if result[0].get("result"):
				num_results = 1
				if isinstance(result[0].get("result"), list):
					num_results = len(result[0].get("result"))
			logger.debug("num_results: %s", num_results)
			redis_key = f"opsiconfd:stats:rpc:{rpc_count}:{result[0].get('method')}"
			async with await redis_client.pipeline(transaction=False) as pipe:
				await pipe.hmset(redis_key, {"num_params": len(params), "error": error,"num_results": num_results, "duration": result[1]})
				await pipe.expire(redis_key, 172800)
				redis_returncode = await pipe.execute()

		#print(f"done {myid}")
		if len(results) == 1:
			return results[0]
		return results
	except HTTPException as e:
		logger.error(e)
		raise
	except Exception as e:
		logger.error(e, exc_info=True)
		tb = traceback.format_exc()
		error = {"message": str(e), "class": e.__class__.__name__}
		if True:
			error["details"] = str(tb)
		return {"jsonrpc": "2.0", "id": None, "result": None, "error": error}

def process_rpc(request: Request, response: Response, rpc, backend):
	rpc_id = None
	try:
		start = time.perf_counter()
		user_agent = request.headers.get('user-agent')
		method_name = rpc.get('method')
		params = rpc.get('params', [])
		rpc_id = rpc.get('id')
		logger.debug("Processing request from %s (%s) for %s", request.client.host, user_agent, method_name)
		logger.trace("Retrieved parameters %s for %s", params, method_name)

		if method_name == "backend_exit":
			return [None, 0]
		
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
		if keywords:
			result = method(*params, **keywords)
		else:
			result = method(*params)
		params.append(keywords)
		response = {"jsonrpc": "2.0", "id": rpc_id, "method": method_name, "params": params, "result": result, "error": None}
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
		return [{"jsonrpc": "2.0", "id": rpc_id, "method": method_name, "params": params, "result": None, "error": error}, 0]
		
