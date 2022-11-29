# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
jsonrpc
"""

import asyncio
import tempfile
import time
import traceback
import urllib.parse
import warnings
from datetime import datetime
from functools import lru_cache
from os import makedirs
from typing import Any, AsyncGenerator, Dict, List, Optional, Type

import msgspec
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.requests import Request
from fastapi.responses import Response
from opsicommon.messagebus import (  # type: ignore[import]
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
)
from opsicommon.objects import OBJECT_CLASSES, BaseObject  # type: ignore[import]
from starlette.concurrency import run_in_threadpool

from opsiconfd import contextvar_client_session, server_timing
from opsiconfd.backend import get_protected_backend, get_unprotected_backend
from opsiconfd.messagebus import get_messagebus_user_id_for_service_worker
from opsiconfd.session import OPSISession

from ..config import RPC_DEBUG_DIR, config
from ..logging import logger
from ..messagebus.redis import ConsumerGroupMessageReader, send_message
from ..utils import (
	async_redis_client,
	compress_data,
	decode_redis_result,
	decompress_data,
)
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
jsonrpc_message_reader = None  # pylint: disable=invalid-name


def jsonrpc_setup(app: FastAPI) -> None:
	app.include_router(jsonrpc_router, prefix="/rpc")


async def async_jsonrpc_startup() -> None:
	asyncio.create_task(messagebus_jsonrpc_request_worker())


async def async_jsonrpc_shutdown() -> None:
	if jsonrpc_message_reader:
		jsonrpc_message_reader.stop()


async def get_sort_algorithm(algorithm: str = None) -> str:
	if algorithm in ("algorithm1", "algorithm2"):
		return algorithm
	algorithm = "algorithm1"
	result = await get_unprotected_backend().async_call("config_getObjects", id="product_sort_algorithm")
	if result and "algorithm2" in result[0].getDefaultValues():
		algorithm = "algorithm2"
	return algorithm


async def store_product_ordering(result: Dict[str, Any], depot_id: str, sort_algorithm: str | None = None) -> None:
	try:
		sort_algorithm = await get_sort_algorithm(sort_algorithm)
		redis = await async_redis_client()
		async with redis.pipeline() as pipe:
			sort_algorithm_key = f"opsiconfd:jsonrpccache:{depot_id}:products:{sort_algorithm}"
			products_key = f"opsiconfd:jsonrpccache:{depot_id}:products"
			pipe.unlink(products_key)
			pipe.unlink(sort_algorithm_key)
			for val in result.get("not_sorted", []):
				pipe.zadd(products_key, {val: 1})
			pipe.expire(products_key, EXPIRE)
			for idx, val in enumerate(result.get("sorted", [])):
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


async def set_jsonrpc_cache_outdated(params: List[Any]) -> None:
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


async def remove_depot_from_jsonrpc_cache(depot_id: str) -> None:
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
	if content_encoding == "identity":
		return None
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


msgpack_decoder = msgspec.msgpack.Decoder()
json_decoder = msgspec.json.Decoder()


def deserialize_data(data: bytes, serialization: str) -> Any:
	if serialization == "msgpack":
		return msgpack_decoder.decode(data)
	if serialization == "json":
		return json_decoder.decode(data)
	raise ValueError(f"Unhandled serialization {serialization!r}")


msgpack_encoder = msgspec.msgpack.Encoder()
json_encoder = msgspec.json.Encoder()


def serialize_data(data: Any, serialization: str) -> bytes:
	if serialization == "msgpack":
		return msgpack_encoder.encode(data)
	if serialization == "json":
		return json_encoder.encode(data)  # pylint: disable=no-member
	raise ValueError(f"Unhandled serialization {serialization!r}")


async def load_from_cache(rpc: Any) -> Optional[Any]:
	if rpc["method"] in PRODUCT_METHODS:
		await set_jsonrpc_cache_outdated(rpc["params"])
		return None
	if rpc["method"] in ("deleteDepot", "host_delete"):
		await remove_depot_from_jsonrpc_cache(rpc["params"][0])
		return None
	if rpc["method"] == "getProductOrdering":
		depot = rpc["params"][0]
		backend = get_unprotected_backend()
		cache_outdated = backend.config_getIdents(id=f"opsiconfd.{depot}.product.cache.outdated")  # type: ignore[union-attr]  # pylint: disable=no-member
		algorithm = await get_sort_algorithm(rpc["params"])
		redis = await async_redis_client()
		if cache_outdated:
			backend.config_delete(id=f"opsiconfd.{depot}.product.cache.outdated")  # pylint: disable=no-member
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


async def store_rpc_info(rpc: Any, result: Dict[str, Any], duration: float, date: datetime, client_info: str) -> None:
	is_error = bool(result.get("error"))
	worker = Worker.get_instance()
	metrics_collector = worker.metrics_collector
	if metrics_collector and not is_error:
		await metrics_collector.add_value(
			"worker:avg_jsonrpc_duration", duration, {"node_name": config.node_name, "worker_num": worker.worker_num}
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
		"client": client_info,
		"error": is_error,
		"num_results": num_results,
		"duration": duration,
		"worker": worker.worker_num,
	}
	logger.notice(
		"JSONRPC request: method=%s, num_params=%d, duration=%0.0fms, error=%s, num_results=%d, worker=%d",
		data["method"],
		data["num_params"],
		data["duration"] * 1000,
		data["error"],
		data["num_results"],
		worker.worker_num
	)

	max_rpcs = 9999
	async with redis.pipeline() as pipe:
		pipe.lpush("opsiconfd:stats:rpcs", msgspec.msgpack.encode(data))  # pylint: disable=c-extension-no-member
		pipe.ltrim("opsiconfd:stats:rpcs", 0, max_rpcs - 1)
		await pipe.execute()


def execute_rpc(client_info: str, rpc: Dict[str, Any]) -> Any:
	method_name = rpc["method"]
	params = rpc["params"]
	backend = get_protected_backend()

	method_interface = backend.get_method_interface(method_name)
	if not method_interface:
		logger.warning("Invalid method %r", method_name)
		raise ValueError(f"Invalid method {method_name!r}")

	with server_timing("deserialize_objects"):
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

	method = getattr(backend, method_name)

	if getattr(method, "deprecated", False):
		warnings.warn(
			f"Client {client_info} is calling deprecated method {method_name!r}",
			DeprecationWarning
		)

	with server_timing("method_execution"):
		result = method(*params, **keywords)

	with server_timing("serialize_objects"):
		return serialize(result)


def serialize(obj: Any, deep: bool = False) -> Any:
	# This is performance critical!
	if isinstance(obj, list):
		return [serialize(o, deep) for o in obj]
	if isinstance(obj, BaseObject):
		return obj.serialize()
	if not deep:
		return obj
	if isinstance(obj, dict):
		return {k: serialize(v, deep) for k, v in obj.items()}
	return obj


@lru_cache(maxsize=0)
def get_object_type(object_type: str) -> Type[BaseObject] | None:
	return OBJECT_CLASSES.get(object_type)


def deserialize(obj: Any, deep: bool = False) -> Any:  # pylint: disable=invalid-name
	# This is performance critical!
	if isinstance(obj, list):
		return [deserialize(o) for o in obj]
	if isinstance(obj, dict):
		try:
			obj_type = get_object_type(obj["type"])
			return obj_type.fromHash(obj)  # type: ignore[union-attr]
		except KeyError:
			pass
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
			raise ValueError(f"Failed to create object from dict {obj}: {err}") from err
	if not deep:
		return obj
	if isinstance(obj, dict):
		return {k: deserialize(v) for k, v in obj.items()}
	return obj


def write_error_log(client_info: str, exception: Exception, rpc: Dict[str, Any] = None) -> None:
	now = int(time.time() * 1_000_000)
	makedirs(RPC_DEBUG_DIR, exist_ok=True)
	method = None
	params = None
	if rpc:
		method = rpc.get("method")
		params = rpc.get("params")
	msg = {
		"client": client_info,
		"description": f"Processing request from {client_info} for method {method!r}",
		"method": method,
		"params": params,
		"error": str(exception),
	}
	prefix = f"{client_info}-{now}-".replace("/", "_").replace(".", "_")
	with tempfile.NamedTemporaryFile(
		delete=False, dir=RPC_DEBUG_DIR, prefix=prefix, suffix=".log"
	) as log_file:
		logger.notice("Writing rpc error log to: %s", log_file.name)
		log_file.write(msgspec.json.encode(msg))  # pylint: disable=no-member


async def process_rpc_error(client_info: str, exception: Exception, rpc: Dict[str, Any] = None) -> Any:
	if config.debug_options and "rpc-error-log" in config.debug_options:
		try:
			await run_in_threadpool(write_error_log, client_info, exception, rpc)
		except Exception as write_err:  # pylint: disable=broad-except
			logger.warning(write_err, exc_info=True)

	_id = rpc.get("id") if rpc else None
	message = str(exception)
	_class = exception.__class__.__name__
	details = None
	try:
		session = contextvar_client_session.get()
		if session and session.is_admin:
			details = str(traceback.format_exc())
	except Exception as sess_err:  # pylint: disable=broad-except
		logger.warning(sess_err, exc_info=True)

	if rpc and rpc.get("jsonrpc") == "2.0":
		return {
			"jsonrpc": "2.0",
			"id": _id,
			"error": {
				"code": 0,  # TODO
				"message": message,
				"data": {"class": _class, "details": details}
			}
		}

	return {
		"id": 0 if _id is None else _id,
		"result": None,
		"error": {
			"message": message,
			"class": _class,
			"details": details
		}
	}


async def process_rpc(client_info: str, rpc: Dict[str, Any]) -> Dict[str, Any]:
	if "id" not in rpc:
		rpc["id"] = 0
	if "params" not in rpc:
		rpc["params"] = []
	if "method" not in rpc:
		raise ValueError("Key 'method' missing in rpc")

	logger.debug("Method '%s', params (short): %.250s", rpc["method"], rpc["params"])
	logger.trace("Method '%s', params (full): %s", rpc["method"], rpc["params"])

	result = await load_from_cache(rpc)
	if result is None:
		result = await run_in_threadpool(execute_rpc, client_info, rpc)

	if rpc.get("jsonrpc") == "2.0":
		return {"jsonrpc": "2.0", "id": rpc["id"], "result": result}

	return {"id": rpc["id"], "result": result, "error": None}


async def process_rpcs(client_info: str, *rpcs: Dict[str, Any]) -> AsyncGenerator[Dict[str, Any], None]:
	worker = Worker.get_instance()
	metrics_collector = worker.metrics_collector
	if metrics_collector:
		asyncio.get_running_loop().create_task(
			metrics_collector.add_value(
				"worker:sum_jsonrpc_number", len(rpcs), {"node_name": config.node_name, "worker_num": worker.worker_num}
			)
		)

	for rpc in rpcs:
		date = datetime.utcnow()
		with server_timing("rpc_processing") as svt:
			try:  # pylint: disable=loop-try-except-usage
				logger.debug("Processing request from %s for %s", client_info, rpc["method"])
				result = await process_rpc(client_info, rpc)
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
				result = await process_rpc_error(client_info, err, rpc)

		duration = svt["rpc_processing"] / 1000  # pylint: disable=loop-invariant-statement

		logger.trace(result)
		yield result

		if not result.get("error") and duration > config.jsonrpc_time_to_cache:
			await store_in_cache(rpc, result)

		asyncio.create_task(store_rpc_info(rpc, result, duration, date, client_info))  # pylint: disable=dotted-import-in-loop


# Some clients are using /rpc/rpc
@jsonrpc_router.get("")
@jsonrpc_router.post("")
@jsonrpc_router.get("{any:path}")
@jsonrpc_router.post("{any:path}")
async def process_request(request: Request, response: Response) -> Response:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	request_compression = None
	request_serialization = None
	response_compression = None
	response_serialization = None
	client_info = ""
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

		request_data = await request.body()
		if not isinstance(request_data, bytes):
			raise ValueError("Request data must be bytes")
		if request_data:
			if request_compression:
				with server_timing("decompression"):
					request_data = await run_in_threadpool(decompress_data, request_data, request_compression)
		else:
			request_data = urllib.parse.unquote(request.url.query).encode("utf-8")
		if not request_data:
			raise ValueError("Request data empty")

		with server_timing("deserialization"):
			rpcs = await run_in_threadpool(deserialize_data, request_data, request_serialization)
		logger.trace("rpcs: %s", rpcs)
		client_info = f"{request.scope['client'][0]}/{request.headers.get('user-agent', '')}"
		if isinstance(rpcs, list):
			coro = process_rpcs(client_info, *rpcs)
		else:
			coro = process_rpcs(client_info, rpcs)
		results = [result async for result in coro]
		response.status_code = 200
	except HTTPException as err:  # pylint: disable=broad-except
		logger.error(err)
		raise
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		results = [await process_rpc_error(client_info, err)]  # pylint: disable=use-tuple-over-list
		response.status_code = 400

	response_serialization = response_serialization or "json"
	response.headers["content-type"] = f"application/{response_serialization}"
	with server_timing("serialization"):
		data = await run_in_threadpool(serialize_data, results[0] if len(results) == 1 else results, response_serialization)

	data_len = len(data)
	if response_compression and data_len > COMPRESS_MIN_SIZE:
		response.headers["content-encoding"] = response_compression
		lz4_block_linked = True
		if request.headers.get("user-agent", "").startswith("opsi config editor"):
			# lz4-java - RuntimeException: Dependent block stream is unsupported (BLOCK_INDEPENDENCE must be set).
			lz4_block_linked = False
		with server_timing("compression"):
			data = await run_in_threadpool(compress_data, data, response_compression, 0, lz4_block_linked)

	content_length = len(data)
	response.headers["content-length"] = str(content_length)
	response.body = data
	logger.debug("Sending result (len: %d)", content_length)
	return response


async def _process_message(cgmr: ConsumerGroupMessageReader, redis_id: str, message: Message, context: Any) -> None:
	if not isinstance(message, JSONRPCRequestMessage):
		logger.error("Wrong message type: %s", type(message))
		# ACK Message
		await cgmr.ack_message(message.channel, redis_id)
		return

	if context:
		session = OPSISession.from_serialized(context)
		contextvar_client_session.set(session)

	client_info = message.sender
	rpc = {
		"jsonrpc": "2.0",
		"id": message.rpc_id,
		"method": message.method,
		"params": message.params
	}

	try:
		result = await anext(process_rpcs(client_info, rpc))
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		result = await process_rpc_error(client_info, err)

	response_message = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
		sender=cgmr.consumer_name,
		channel=message.back_channel,
		ref_id=message.id,
		rpc_id=result["id"],
		result=result.get("result"),
		error=result.get("error")
	)

	# asyncio.create_task(send_message(response_message))
	await send_message(response_message)
	# ACK Message
	# asyncio.create_task(cgmr.ack_message(redis_id))
	await cgmr.ack_message(message.channel, redis_id)


async def messagebus_jsonrpc_request_worker() -> None:
	global jsonrpc_message_reader  # pylint: disable=invalid-name,global-statement

	worker = Worker.get_instance()
	messagebus_worker_id = get_messagebus_user_id_for_service_worker(config.node_name, worker.worker_num)
	channel = "service:config:jsonrpc"

	jsonrpc_message_reader = ConsumerGroupMessageReader(consumer_group=channel, consumer_name=messagebus_worker_id, channels={channel: "0"})
	async for redis_id, message, context in jsonrpc_message_reader.get_messages():
		try:
			await _process_message(jsonrpc_message_reader, redis_id, message, context)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
