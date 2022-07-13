# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
jsonrpc
"""

import asyncio
import gzip
import tempfile
import time
import traceback
import urllib.parse
import warnings
import zlib
from datetime import datetime
from os import makedirs
from time import perf_counter
from typing import Any, Dict, List, Optional, Union

import lz4.frame  # type: ignore[import]
import msgpack  # type: ignore[import]
import orjson
from fastapi import APIRouter, HTTPException
from fastapi.requests import Request
from fastapi.responses import Response
from OPSI.Util import deserialize, serialize  # type: ignore[import]
from starlette.concurrency import run_in_threadpool

from .. import contextvar_client_session
from ..backend import (
	BackendManager,
	OpsiconfdBackend,
	async_backend_call,
	get_backend,
	get_backend_interface,
	get_client_backend,
)
from ..config import RPC_DEBUG_DIR, config
from ..logging import logger
from ..statistics import GrafanaPanelConfig, Metric, metrics_registry
from ..utils import async_redis_client, decode_redis_result
from ..worker import Worker

# time in seconds
EXPIRE = 24 * 3600
EXPIRE_UPTODATE = 24 * 3600
COMPRESS_MIN_SIZE = 10000

PRODUCT_METHODS = (
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
	"productOnDepot_updateObjects",
)

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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
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
		downsampling=[
			["minute", 24 * 3600 * 1000, "avg"],
			["hour", 60 * 24 * 3600 * 1000, "avg"],
			["day", 4 * 365 * 24 * 3600 * 1000, "avg"],
		],
	),
)


def jsonrpc_setup(app):
	app.include_router(jsonrpc_router, prefix="/rpc")


async def get_sort_algorithm(algorithm: str = None):
	if algorithm in ("algorithm1", "algorithm2"):
		return algorithm
	algorithm = "algorithm1"
	result = await async_backend_call("config_getObjects", id="product_sort_algorithm")
	if result and "algorithm2" in result[0].getDefaultValues():
		algorithm = "algorithm2"
	return algorithm


async def store_product_ordering(result, depot_id, sort_algorithm=None):
	try:
		sort_algorithm = await get_sort_algorithm(sort_algorithm)
		redis = await async_redis_client()
		async with redis.pipeline() as pipe:
			sort_algorithm_key = f"opsiconfd:jsonrpccache:{depot_id}:products:{sort_algorithm}"
			products_key = f"opsiconfd:jsonrpccache:{depot_id}:products"
			pipe.unlink(products_key)
			pipe.unlink(sort_algorithm_key)
			for val in result.get("not_sorted"):
				pipe.zadd(products_key, {val: 1})
			pipe.expire(products_key, EXPIRE)
			for idx, val in enumerate(result.get("sorted")):
				pipe.zadd(sort_algorithm_key, {val: idx})
			pipe.expire(sort_algorithm_key, EXPIRE)
			now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
			pipe.set(f"opsiconfd:jsonrpccache:{depot_id}:products:uptodate", now)
			pipe.set(f"opsiconfd:jsonrpccache:{depot_id}:products:{sort_algorithm}:uptodate", now)
			pipe.expire(f"opsiconfd:jsonrpccache:{depot_id}:products:uptodate", EXPIRE_UPTODATE)
			pipe.expire(f"opsiconfd:jsonrpccache:{depot_id}:products:{sort_algorithm}:uptodate", EXPIRE_UPTODATE)
			pipe.sadd("opsiconfd:jsonrpccache:depots", depot_id)
			await pipe.execute()
	except Exception as err:  # pylint: disable=broad-except
		logger.error(
			"Failed to store product ordering cache depot_id=%s, sort_algorithm=%s: %s", depot_id, sort_algorithm, err, exc_info=True
		)


async def set_jsonrpc_cache_outdated(params):
	redis = await async_redis_client()
	saved_depots = decode_redis_result(await redis.smembers("opsiconfd:jsonrpccache:depots"))
	str_params = str(params)
	depots = [depot for depot in saved_depots if str_params.find(depot) != -1]
	if len(depots) == 0:
		depots = saved_depots

	async with redis.pipeline() as pipe:
		for depot_id in depots:
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:uptodate")
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1:uptodate")
			pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm2:uptodate")
		await pipe.execute()


async def remove_depot_from_jsonrpc_cache(depot_id):
	redis = await async_redis_client()
	async with redis.pipeline() as pipe:
		pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products")
		pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:uptodate")
		pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1")
		pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm1:uptodate")
		pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm2")
		pipe.delete(f"opsiconfd:jsonrpccache:{depot_id}:products:algorithm2:uptodate")
		pipe.srem("opsiconfd:jsonrpccache:depots", depot_id)
		await pipe.execute()


def get_compression(content_encoding: str) -> Optional[str]:
	if not content_encoding:
		return None
	content_encoding = content_encoding.lower()
	if "lz4" in content_encoding:
		return "lz4"
	if "deflate" in content_encoding:
		return "deflate"
	if "gzip" in content_encoding:
		return "gzip"
	raise ValueError(f"Unhandled Content-Encoding {content_encoding!r}")


def get_request_compression(request: Request) -> Optional[str]:
	content_encoding = request.headers.get("content-encoding", "")
	logger.debug("Content-Encoding: %r", content_encoding)
	return get_compression(content_encoding)


def get_response_compression(request: Request) -> Optional[str]:
	content_encoding = request.headers.get("accept-encoding", "")
	logger.debug("Accept-Encoding: %r", content_encoding)
	return get_compression(content_encoding)


def get_request_serialization(request: Request) -> Optional[str]:
	content_type = request.headers.get("content-type")
	logger.debug("Content-Type: %r", content_type)
	if content_type:
		content_type = content_type.lower()
		if "msgpack" in content_type:
			return "msgpack"
		if "json" in content_type:
			return "json"
	return None


def get_response_serialization(request: Request) -> Optional[str]:
	accept = request.headers.get("accept")
	logger.debug("Accept: %r", accept)
	if accept:
		accept = accept.lower()
		if "msgpack" in accept:
			return "msgpack"
		if "json" in accept:
			return "json"
	return None


def decompress_data(data: bytes, compression: str) -> bytes:
	compressed_size = len(data)

	decompress_start = time.perf_counter()
	if compression == "lz4":
		data = lz4.frame.decompress(data)
	elif compression == "deflate":
		data = zlib.decompress(data)
	elif compression == "gzip":
		data = gzip.decompress(data)
	else:
		raise ValueError(f"Unhandled compression {compression!r}")
	decompress_end = time.perf_counter()

	uncompressed_size = len(data)
	logger.debug(
		"%s decompression ratio: %d => %d = %0.2f%%, time: %0.2fms",
		compression,
		compressed_size,
		uncompressed_size,
		100 - 100 * (compressed_size / uncompressed_size),
		1000 * (decompress_end - decompress_start),
	)
	return data


def compress_data(data: bytes, compression: str, compression_level: int = 0, lz4_block_linked: bool = True) -> bytes:
	uncompressed_size = len(data)

	compress_start = time.perf_counter()
	if compression == "lz4":
		data = lz4.frame.compress(data, compression_level=compression_level, block_linked=lz4_block_linked)
	elif compression == "deflate":
		data = zlib.compress(data)
	elif compression == "gzip":
		data = gzip.compress(data)
	else:
		raise ValueError(f"Unhandled compression {compression!r}")
	compress_end = time.perf_counter()

	compressed_size = len(data)
	logger.debug(
		"%s compression ratio: %d => %d = %0.2f%%, time: %0.2fms",
		compression,
		uncompressed_size,
		compressed_size,
		100 - 100 * (compressed_size / uncompressed_size),
		1000 * (compress_end - compress_start),
	)
	return data


def deserialize_data(data: Union[bytes, str], serialization: str) -> Any:
	deserialize_start = time.perf_counter()
	if serialization == "msgpack":
		result = msgpack.loads(data)
	elif serialization == "json":
		if isinstance(data, bytes):
			# workaround for "JSONDecodeError: str is not valid UTF-8: surrogates not allowed".
			# opsi-script produces invalid UTF-8.
			# Therefore we do not pass bytes to orjson.loads but
			# decoding with "replace" first and passing unicode to orjson.loads.
			# See orjson documentation for details.
			data = data.decode("utf-8", "replace")
		result = orjson.loads(data)  # pylint: disable=no-member
	else:
		raise ValueError(f"Unhandled serialization {serialization!r}")
	deserialize_end = time.perf_counter()
	logger.debug(
		"%s deserialization time: %0.2fms",
		serialization,
		1000 * (deserialize_end - deserialize_start),
	)
	return result


def serialize_data(data: Any, serialization: str) -> bytes:
	if serialization == "msgpack":
		return msgpack.dumps(data)
	if serialization == "json":
		return orjson.dumps(data)  # pylint: disable=no-member
	raise ValueError(f"Unhandled serialization {serialization!r}")


async def load_from_cache(rpc: Any, backend: Union[OpsiconfdBackend, BackendManager]) -> Optional[Any]:
	if rpc["method"] in PRODUCT_METHODS:
		await set_jsonrpc_cache_outdated(rpc["params"])
		return None
	if rpc["method"] in ("deleteDepot", "host_delete"):
		await remove_depot_from_jsonrpc_cache(rpc["params"][0])
		return None
	if rpc["method"] == "getProductOrdering":
		depot = rpc["params"][0]
		cache_outdated = backend.config_getIdents(id=f"opsiconfd.{depot}.product.cache.outdated")  # type: ignore[union-attr]  # pylint: disable=no-member
		algorithm = await get_sort_algorithm(rpc["params"])
		redis = await async_redis_client()
		if cache_outdated:
			get_backend().config_delete(id=f"opsiconfd.{depot}.product.cache.outdated")  # pylint: disable=no-member
			async with redis.pipeline() as pipe:
				pipe.unlink(f"opsiconfd:jsonrpccache:{depot}:products:uptodate")
				pipe.unlink(f"opsiconfd:jsonrpccache:{depot}:products:algorithm1:uptodate")
				pipe.unlink(f"opsiconfd:jsonrpccache:{depot}:products:algorithm2:uptodate")
				await pipe.execute()
			return None

		async with redis.pipeline() as pipe:
			pipe.get(f"opsiconfd:jsonrpccache:{depot}:products:uptodate")
			pipe.get(f"opsiconfd:jsonrpccache:{depot}:products:{algorithm}:uptodate")
			pipe_results = await pipe.execute()
		products_uptodate, sorted_uptodate = pipe_results
		if not products_uptodate or not sorted_uptodate:
			return None

		depot_id = rpc["params"][0]
		algorithm = await get_sort_algorithm(rpc["params"])
		redis = await async_redis_client()
		async with redis.pipeline() as pipe:
			pipe.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products", 0, -1)
			pipe.zrange(f"opsiconfd:jsonrpccache:{depot_id}:products:{algorithm}", 0, -1)
			pipe.expire(f"opsiconfd:jsonrpccache:{depot_id}:products", EXPIRE)
			pipe.expire(f"opsiconfd:jsonrpccache:{depot_id}:products:{algorithm}", EXPIRE)
			pipe_results = await pipe.execute()
		products = pipe_results[0]
		products_ordered = pipe_results[1]
		return {"not_sorted": decode_redis_result(products), "sorted": decode_redis_result(products_ordered)}
	return None


async def store_in_cache(rpc: Any, result: Dict[str, Any]) -> None:
	if rpc["method"] == "getProductOrdering":
		if 1 <= len(rpc["params"]) <= 2 and len(result["result"].get("sorted", [])) > 0:
			logger.debug("Storing product ordering in cache")
			await store_product_ordering(result["result"], *rpc["params"])


async def store_rpc_info(rpc: Any, result: Dict[str, Any], duration: float, date: datetime, client: str):
	is_error = bool(result.get("error"))
	worker = Worker()
	metrics_collector = worker.metrics_collector
	if metrics_collector and not is_error:
		asyncio.get_running_loop().create_task(
			metrics_collector.add_value(
				"worker:avg_jsonrpc_duration", duration, {"node_name": config.node_name, "worker_num": worker.worker_num}
			)
		)

	redis = await async_redis_client()
	rpc_num = await redis.incr("opsiconfd:stats:num_rpcs")

	num_params = 0
	if rpc.get("params"):
		num_params = 1
		if isinstance(rpc["params"], list):
			num_params = len(rpc["params"])

	num_results = 0
	if result.get("result"):
		num_results = 1
		if isinstance(result["result"], list):
			num_results = len(result["result"])

	data = {
		"rpc_num": rpc_num,
		"method": rpc.get("method"),
		"num_params": num_params,
		"date": date.strftime("%Y-%m-%dT%H:%M:%SZ"),
		"client": client,
		"error": is_error,
		"num_results": num_results,
		"duration": duration,
		"worker": worker.worker_num,
	}
	logger.notice(
		"JSONRPC request: method=%s, num_params=%d, duration=%0.4f, error=%s, num_results=%d",
		data["method"],
		data["num_params"],
		data["duration"],
		data["error"],
		data["num_results"],
	)

	max_rpcs = 9999
	async with redis.pipeline() as pipe:
		pipe.lpush("opsiconfd:stats:rpcs", msgpack.dumps(data))  # pylint: disable=c-extension-no-member
		pipe.ltrim("opsiconfd:stats:rpcs", 0, max_rpcs - 1)
		await pipe.execute()


def execute_rpc(rpc: Any, backend: Union[OpsiconfdBackend, BackendManager], request: Request) -> Any:
	method_name = rpc["method"]
	params = rpc["params"]
	method_interface = None
	for interface_method in get_backend_interface():
		if method_name == interface_method["name"]:
			method_interface = interface_method
			break
	if not method_interface:
		raise ValueError(f"Invalid method {method_name!r}")

	keywords = {}
	if method_interface["keywords"]:
		parameter_count = 0
		if method_interface["args"]:
			parameter_count += len(method_interface["args"])
		if method_interface["varargs"]:
			parameter_count += len(method_interface["varargs"])

		if len(params) >= parameter_count:
			# params needs to be a copy, leave rpc["params"] unchanged
			kwargs = params[-1]
			params = params[:-1]
			if not isinstance(kwargs, dict):
				raise TypeError(f"kwargs param is not a dict: {type(kwargs)}")
			keywords = {str(key): deserialize(value) for key, value in kwargs.items()}
	params = deserialize(params)

	if method_name in OpsiconfdBackend().method_names:
		method = getattr(OpsiconfdBackend(), method_name)
	else:
		method = getattr(backend, method_name)

	if getattr(method, "deprecated", False):
		warnings.warn(
			f"Client {request.scope['client'][0]!r} ({request.headers.get('user-agent', '')!r}) "
			f"is calling deprecated method {method_name!r}",
			DeprecationWarning
		)

	return serialize(method(*params, **keywords))


def write_error_log(rpc: Any, exception: Exception, request: Request) -> None:
	now = int(time.time() * 1_000_000)
	makedirs(RPC_DEBUG_DIR, exist_ok=True)
	method = None
	params = None
	if rpc:
		method = rpc.get("method")
		params = rpc.get("params")
	msg = {
		"client": request.scope["client"][0],
		"description": f"Processing request from {request.scope['client'][0]!r} ({request.headers.get('user-agent')}) for method {method!r}",
		"method": method,
		"params": params,
		"error": str(exception),
	}
	with tempfile.NamedTemporaryFile(
		delete=False, dir=RPC_DEBUG_DIR, prefix=f"{request.scope['client'][0]}-{now}-", suffix=".log"
	) as log_file:
		logger.notice("Writing rpc error log to: %s", log_file.name)
		log_file.write(orjson.dumps(msg))  # pylint: disable=no-member


async def process_rpc_error(exception: Exception, request: Request, rpc: Any = None) -> Any:
	if config.debug_options and "rpc-error-log" in config.debug_options:
		try:
			await run_in_threadpool(write_error_log, rpc, exception, request)
		except Exception as write_err:  # pylint: disable=broad-except
			logger.warning(write_err, exc_info=True)

	result = {"id": rpc.get("id", 0) if rpc else 0, "error": {"message": str(exception), "class": exception.__class__.__name__}}
	if rpc and rpc.get("jsonrpc") == "2.0":
		result["jsonrpc"] = "2.0"
	else:
		result["result"] = None

	try:
		session = contextvar_client_session.get()
		if session and session.user_store.isAdmin:
			result["error"]["details"] = str(traceback.format_exc())
	except Exception as sess_err:  # pylint: disable=broad-except
		logger.warning(sess_err, exc_info=True)

	return result


async def process_rpc(rpc: Any, request: Request):
	if "id" not in rpc:
		rpc["id"] = 0
	if "params" not in rpc:
		rpc["params"] = []
	if "method" not in rpc:
		raise ValueError("Key 'method' missing in rpc")

	if rpc["method"] in OpsiconfdBackend().method_names:
		backend = OpsiconfdBackend()
	else:
		backend = get_client_backend()

	user_agent = request.headers.get("user-agent")
	logger.debug("Processing request from %s (%s) for %s", request.scope["client"][0], user_agent, rpc["method"])
	logger.debug("Method '%s', params (short): %.250s", rpc["method"], rpc["params"])
	logger.trace("Method '%s', params (full): %s", rpc["method"], rpc["params"])

	result = await load_from_cache(rpc, backend)
	if result is None:
		result = await run_in_threadpool(execute_rpc, rpc, backend, request)

	response = {"id": rpc["id"], "result": result, "error": None}
	if rpc.get("jsonrpc") == "2.0":
		response["jsonrpc"] = "2.0"
		del response["error"]

	return response


async def process_rpcs(rpcs: Any, request: Request) -> List[Dict[str, Any]]:
	if not isinstance(rpcs, list):
		rpcs = (rpcs,)

	worker = Worker()
	metrics_collector = worker.metrics_collector
	if metrics_collector:
		asyncio.get_running_loop().create_task(
			metrics_collector.add_value(
				"worker:sum_jsonrpc_number", len(rpcs), {"node_name": config.node_name, "worker_num": worker.worker_num}
			)
		)

	client_addr = request.scope["client"][0]
	results = []
	for rpc in rpcs:
		date = datetime.utcnow()
		start = perf_counter()
		try:  # pylint: disable=loop-try-except-usage
			result = await process_rpc(rpc, request)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
			result = await process_rpc_error(err, request, rpc)

		duration = perf_counter() - start

		logger.trace(result)
		results.append(result)

		if not result.get("error") and duration > config.jsonrpc_time_to_cache:
			await store_in_cache(rpc, result)

		await store_rpc_info(rpc, result, duration, date, client_addr)
	return results


# Some clients are using /rpc/rpc
@jsonrpc_router.get("")
@jsonrpc_router.post("")
@jsonrpc_router.get("{any:path}")
@jsonrpc_router.post("{any:path}")
async def process_request(request: Request, response: Response):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	request_compression = None
	request_serialization = None
	response_compression = None
	response_serialization = None
	try:
		request_serialization = get_request_serialization(request)
		if request_serialization:
			# Always using same response serialization as request serialization
			response_serialization = request_serialization
		else:
			logger.debug("Unhandled request serialization %r, using json", request_serialization)
			request_serialization = "json"
			response_serialization = get_response_serialization(request)
			if not response_serialization:
				logger.debug("test_compression response serialization %r, using json", response_serialization)
				response_serialization = "json"

		response_compression = get_response_compression(request)
		request_compression = get_request_compression(request)

		request_data: Union[bytes, str] = await request.body()
		if request_data:
			if request_compression:
				request_data = await run_in_threadpool(decompress_data, request_data, request_compression)
		else:
			request_data = urllib.parse.unquote(request.url.query)
		if not request_data:
			raise ValueError("Request data empty")

		rpcs = await run_in_threadpool(deserialize_data, request_data, request_serialization)
		logger.trace("rpcs: %s", rpcs)
		results = await process_rpcs(rpcs, request)
		response.status_code = 200
	except HTTPException as err:  # pylint: disable=broad-except
		logger.error(err)
		raise
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		results = [await process_rpc_error(err, request)]  # pylint: disable=use-tuple-over-list
		response.status_code = 400

	response_serialization = response_serialization or "json"
	response.headers["content-type"] = f"application/{response_serialization}"
	data = await run_in_threadpool(serialize_data, results[0] if len(results) == 1 else results, response_serialization)

	data_len = len(data)
	if response_compression and data_len > COMPRESS_MIN_SIZE:
		response.headers["content-encoding"] = response_compression
		lz4_block_linked = True
		if request.headers.get("user-agent", "").startswith("opsi config editor"):
			# lz4-java - RuntimeException: Dependent block stream is unsupported (BLOCK_INDEPENDENCE must be set).
			lz4_block_linked = False
		data = await run_in_threadpool(compress_data, data, response_compression, 0, lz4_block_linked)

	content_length = len(data)
	response.headers["content-length"] = str(content_length)
	response.body = data
	logger.debug("Sending result (len: %d)", content_length)
	return response
