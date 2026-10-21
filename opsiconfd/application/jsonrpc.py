# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
jsonrpc
"""

from __future__ import annotations

import re
import tempfile
import time
import traceback
import urllib.parse
import warnings
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from inspect import iscoroutinefunction
from os import makedirs
from queue import Empty, Queue
from types import GeneratorType
from typing import TYPE_CHECKING, Any, Literal, cast

import msgspec
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.requests import Request
from fastapi.responses import Response
from opsi.compression import compress, decompress
from opsi.opsi.messagebus import (
	CONNECTION_USER_CHANNEL,
	ChannelSubscriptionRequestMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
)
from opsi.opsi.service.client import Messagebus, MessagebusListener
from opsi.opsi.service.model.object import BaseObject, Relationship, deserialize, get_ident_attributes
from opsi.opsi.service.model.type import to_string
from starlette.concurrency import run_in_threadpool

from opsiconfd import contextvar_client_session, server_timing
from opsiconfd.backend import get_protected_backend, get_service_client, get_unprotected_backend
from opsiconfd.config import DEPRECATED_RPC_CALL_EXPIRE_SECONDS, RPC_DEBUG_DIR, config, get_depotserver_id, get_server_role
from opsiconfd.logging import logger
from opsiconfd.messagebus import get_messagebus_worker_id
from opsiconfd.messagebus.redis import ConsumerGroupMessageReader, send_message
from opsiconfd.redis import async_redis_client
from opsiconfd.session import OPSISession
from opsiconfd.utils import asyncio_create_task
from opsiconfd.worker import Worker

if TYPE_CHECKING:
	from opsiconfd.backend.rpc import MethodInterface
	from opsiconfd.backend.rpc.main import ProtectedBackend, UnprotectedBackend


COMPRESS_MIN_SIZE = 10000
AWAIT_STORE_RPC_INFO = False
# Request bodies up to this size are decompressed and deserialized directly in the event loop.
# Compressed bodies are limited to a quarter of this size because of the decompressed size.
INLINE_MAX_REQUEST_SIZE = 16_000
# Responses up to these limits are serialized directly in the event loop (see is_small_data).
SMALL_DATA_MAX_ITEMS = 1000
SMALL_DATA_MAX_STR_LEN = 64_000
# lz4 is fast enough to compress data up to this size directly in the event loop.
LZ4_INLINE_MAX_SIZE = 256_000

jsonrpc_router = APIRouter()
jsonrpc_message_reader = None


def utcnow() -> datetime:
	return datetime.now(tz=UTC)


@dataclass(kw_only=True)
class RequestInfo:
	client: str = ""
	date: datetime = field(default_factory=utcnow)
	deprecated: bool = False
	duration: float = 0.0


@dataclass(kw_only=True)
class JSONRPCRequest:
	method: str
	id: int | str = 0
	params: list[Any] | tuple[Any, ...] | dict[str, Any] = field(default_factory=list)
	info: RequestInfo = field(default_factory=RequestInfo)


@dataclass
class JSONRPCResponse:
	id: int | str
	result: Any | None = None
	error: None = None


@dataclass
class JSONRPCErrorResponse:
	id: int | str
	error: Any | None
	result: None = None


@dataclass(kw_only=True)
class JSONRPC20Request:
	method: str
	id: int | str = 0
	params: list[Any] | tuple[Any, ...] | dict[str, Any] = field(default_factory=list)
	jsonrpc: str = "2.0"
	info: RequestInfo = field(default_factory=RequestInfo)


@dataclass
class JSONRPC20Response:
	id: int | str
	result: Any
	jsonrpc: str = "2.0"


@dataclass
class JSONRPC20Error:
	message: str
	code: int = 0
	data: dict[str, Any] = field(default_factory=dict)


@dataclass
class JSONRPC20ErrorResponse:
	id: int | str
	error: JSONRPC20Error
	jsonrpc: str = "2.0"


def jsonrpc_setup(app: FastAPI) -> None:
	app.include_router(jsonrpc_router, prefix="/rpc")


async def async_jsonrpc_startup() -> None:
	asyncio_create_task(messagebus_jsonrpc_request_worker())


async def async_jsonrpc_shutdown() -> None:
	if jsonrpc_message_reader:
		await jsonrpc_message_reader.stop()


def get_compression(content_encoding: str) -> Literal["lz4", "deflate", "gzip"] | None:
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
	raise ValueError(f"Invalid Content-Encoding {content_encoding!r}")


def get_request_compression(request: Request) -> Literal["lz4", "deflate", "gzip"] | None:
	content_encoding = request.headers.get("content-encoding", "")
	logger.debug("Content-Encoding: %r", content_encoding)
	return get_compression(content_encoding)


def get_response_compression(request: Request) -> Literal["lz4", "deflate", "gzip"] | None:
	content_encoding = request.headers.get("accept-encoding", "")
	logger.debug("Accept-Encoding: %r", content_encoding)
	return get_compression(content_encoding)


def get_request_serialization(request: Request) -> str | None:
	content_type = request.headers.get("content-type")
	logger.debug("Content-Type: %r", content_type)
	if content_type:
		content_type = content_type.lower()
		if "msgpack" in content_type:
			return "msgpack"
		if "json" in content_type:
			return "json"
	return None


def get_response_serialization(request: Request) -> str | None:
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


def jsonrpc_request_from_dict(data: dict[str, Any], client: str) -> JSONRPCRequest | JSONRPC20Request:
	if data.get("jsonrpc") == "2.0":
		return JSONRPC20Request(
			info=RequestInfo(client=client), id=data.get("id") or 0, method=data["method"], params=data.get("params") or []
		)
	return JSONRPCRequest(info=RequestInfo(client=client), id=data.get("id") or 0, method=data["method"], params=data.get("params") or [])


def jsonrpc_request_from_data(data: bytes, serialization: str, client: str = "") -> list[JSONRPCRequest | JSONRPC20Request]:
	dat = deserialize_data(data, serialization)
	if isinstance(dat, list):
		return [jsonrpc_request_from_dict(d, client) for d in dat]
	return [jsonrpc_request_from_dict(dat, client)]


def decode_request(
	data: bytes, compression: Literal["lz4", "deflate", "gzip"] | None, serialization: str, client: str = ""
) -> list[JSONRPCRequest | JSONRPC20Request]:
	"""
	Decompress and deserialize request data.

	Args:
		data: The request data.
		compression: The compression of the request data or None if not compressed.
		serialization: The serialization of the request data.
		client: The client that sent the request.

	Returns:
		The list of JSON-RPC requests.
	"""
	if compression:
		with server_timing("decompression"):
			data = decompress(data, compression)
	with server_timing("deserialization"):
		return jsonrpc_request_from_data(data, serialization, client)


def is_small_data(data: Any) -> bool:
	"""
	Check if data is small enough to be serialized directly in the event loop.

	The check is aborted as soon as a limit is exceeded, so it is cheap for large data too.

	Args:
		data: The data to check.

	Returns:
		True if the data contains at most SMALL_DATA_MAX_ITEMS container items and
		SMALL_DATA_MAX_STR_LEN characters / bytes in total, False otherwise.
		Data containing values of other types (objects, dataclasses, ...) is never considered small.
	"""
	stack = [data]
	num_items = 0
	str_len = 0
	while stack:
		item = stack.pop()
		if item is None or isinstance(item, (bool, int, float)):
			continue
		if isinstance(item, (str, bytes)):
			str_len += len(item)
			if str_len > SMALL_DATA_MAX_STR_LEN:
				return False
			continue
		if isinstance(item, dict):
			num_items += len(item)
			if num_items > SMALL_DATA_MAX_ITEMS:
				return False
			stack.extend(item.values())
			continue
		if isinstance(item, (list, tuple)):
			num_items += len(item)
			if num_items > SMALL_DATA_MAX_ITEMS:
				return False
			stack.extend(item)
			continue
		return False
	return True


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
		return json_encoder.encode(data)
	raise ValueError(f"Unhandled serialization {serialization!r}")


async def store_deprecated_call(method_name: str, client: str) -> None:
	redis_prefix_stats = config.redis_key("stats")
	redis = await async_redis_client()
	expire_time = DEPRECATED_RPC_CALL_EXPIRE_SECONDS
	async with redis.pipeline() as pipe:
		pipe.sadd(f"{redis_prefix_stats}:rpcs:deprecated:methods", method_name)
		pipe.incr(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:count")
		pipe.expire(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:count", expire_time)
		pipe.sadd(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:clients", client[client.index("/") + 1 :])
		pipe.expire(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:clients", expire_time)
		pipe.set(
			f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:last_call",
			datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
			ex=expire_time,
		)
		await pipe.execute()


# msgpack encoded key "rpc_num" and the encoded placeholder value 0
RPC_NUM_KEY = msgspec.msgpack.encode("rpc_num")
RPC_NUM_PLACEHOLDER = RPC_NUM_KEY + msgspec.msgpack.encode(0)
# KEYS[1]: RPC counter, KEYS[2]: RPC info list
# ARGV[1]: msgpack encoded RPC info up to the rpc_num value, ARGV[2]: rest of the encoded RPC info, ARGV[3]: LTRIM end
# The incremented counter is msgpack encoded as unsigned int with the smallest possible size.
STORE_RPC_INFO_LUA_SCRIPT = """
local num = redis.call("INCR", KEYS[1])
local encoded
if num < 128 then
	encoded = string.char(num)
else
	local prefix, size
	if num < 256 then
		prefix, size = 204, 1
	elseif num < 65536 then
		prefix, size = 205, 2
	elseif num < 4294967296 then
		prefix, size = 206, 4
	else
		prefix, size = 207, 8
	end
	local bytes = ""
	for i = 1, size do
		bytes = string.char(num % 256) .. bytes
		num = math.floor(num / 256)
	end
	encoded = string.char(prefix) .. bytes
end
redis.call("LPUSH", KEYS[2], ARGV[1] .. encoded .. ARGV[2])
redis.call("LTRIM", KEYS[2], 0, tonumber(ARGV[3]))
"""


async def store_rpc_info(
	request: JSONRPC20Request | JSONRPCRequest,
	response: JSONRPC20Response | JSONRPC20ErrorResponse | JSONRPCResponse | JSONRPCErrorResponse,
) -> None:
	worker = Worker.get_instance()

	num_params = 0
	if request.params:
		num_params = len(request.params)

	is_error = True
	num_results = 0
	if not isinstance(response, (JSONRPC20ErrorResponse, JSONRPCErrorResponse)):
		is_error = False
		num_results = 1
		if isinstance(response.result, list):
			num_results = len(response.result)
		if worker.metrics_collector:
			await worker.metrics_collector.add_value("worker:avg_jsonrpc_duration", request.info.duration)

	data = {
		# Placeholder, replaced by the incremented counter in the lua script, must be the first key
		"rpc_num": 0,
		"method": request.method,
		"deprecated": request.info.deprecated,
		"num_params": num_params,
		"date": request.info.date.strftime("%Y-%m-%dT%H:%M:%SZ"),
		"client": request.info.client,
		"error": is_error,
		"num_results": num_results,
		"duration": request.info.duration,
		"worker": worker.worker_num,
	}
	logger.notice(
		"JSONRPC request completed: method=%s, num_params=%d, duration=%0.0fms, error=%s, num_results=%d, worker=%d",
		data["method"],
		data["num_params"],
		request.info.duration * 1000,
		data["error"],
		data["num_results"],
		worker.worker_num,
	)

	max_rpcs = 9999
	redis_prefix_stats = config.redis_key("stats")
	# Split the encoded data at the rpc_num placeholder value
	data_head, data_tail = msgspec.msgpack.encode(data).split(RPC_NUM_PLACEHOLDER, 1)
	redis = await async_redis_client()
	# Increment the RPC counter and store the RPC info in one round trip
	await redis.eval(
		STORE_RPC_INFO_LUA_SCRIPT,
		2,
		f"{redis_prefix_stats}:num_rpcs",
		f"{redis_prefix_stats}:rpcs",
		data_head + RPC_NUM_KEY,
		data_tail,
		max_rpcs - 1,
	)

	if request.info.deprecated:
		await store_deprecated_call(request.method, request.info.client)


def deserialize_params(
	params: list[Any] | tuple[Any, ...] | dict[str, Any], method_interface: MethodInterface
) -> tuple[list[Any] | tuple[Any, ...], dict[str, Any]]:
	"""
	Split JSON-RPC params into positional and keyword arguments and deserialize them.

	Args:
		params: The JSON-RPC params.
		method_interface: The interface of the method to call.

	Returns:
		A tuple of positional and keyword arguments.

	Raises:
		TypeError: If the keyword arguments param is not a dict.
	"""
	if isinstance(params, dict):
		return [], deserialize(params)

	keywords = {}
	if method_interface.keywords:
		parameter_count = 0
		if method_interface.args:
			parameter_count += len(method_interface.args)
		if method_interface.varargs:
			parameter_count += len(method_interface.varargs)

		if len(params) >= parameter_count:
			# params needs to be a copy, leave rpc.params unchanged
			kwargs = params[-1]
			params = params[:-1]
			if not isinstance(kwargs, dict):
				raise TypeError(f"kwargs param is not a dict: {type(kwargs)}")
			keywords = {str(key): deserialize(value) for key, value in kwargs.items()}
	return deserialize(params), keywords


_fast_serializable_classes: dict[type, bool] = {}


def _is_fast_serializable(cls: type[BaseObject]) -> bool:
	try:
		return _fast_serializable_classes[cls]
	except KeyError:
		pass
	fast = (
		cls.serialize in (BaseObject.serialize, Relationship.serialize)
		and cls.to_dict is BaseObject.to_dict
		and cls.getType is BaseObject.getType
		and cls.getIdent is BaseObject.getIdent
		and cls.getIdentAttributes is BaseObject.getIdentAttributes
	)
	_fast_serializable_classes[cls] = fast
	return fast


def _serialize_object(obj: BaseObject) -> dict[str, Any]:
	cls = obj.__class__
	if not _is_fast_serializable(cls):
		return obj.serialize()

	# Same result as BaseObject.serialize() but significantly faster
	data = dict(obj.__dict__)
	data["type"] = cls.__name__
	for key, val in data.items():
		if isinstance(val, date):
			data[key] = val.isoformat()

	ident_values = []
	for attr in get_ident_attributes(cls):
		val = getattr(obj, attr, None)
		if val is None:
			val = ""
		elif type(val) is not str:
			val = to_string(val)
		ident_values.append(val)
	data["ident"] = cls.ident_separator.join(ident_values)
	return data


def serialize_result(obj: Any) -> Any:
	"""
	Serialize the result of a backend method.

	Returns the same result as `opsi.opsi.service.model.object.serialize(obj)`,
	but uses a faster serialization for opsi objects.

	Args:
		obj: The result to serialize.

	Returns:
		The serialized result.
	"""
	if isinstance(obj, (list, set, GeneratorType)):
		return [serialize_result(o) for o in obj]
	if isinstance(obj, BaseObject):
		return _serialize_object(obj)
	return obj


def execute_sync_method(method: Callable, params: list[Any] | tuple[Any, ...] | dict[str, Any], method_interface: MethodInterface) -> Any:
	"""
	Deserialize params, execute a synchronous backend method and serialize the result.

	All steps are executed in the calling thread, to need only one thread pool call per RPC.

	Args:
		method: The backend method to execute.
		params: The JSON-RPC params.
		method_interface: The interface of the method.

	Returns:
		The serialized result.
	"""
	with server_timing("deserialize_objects"):
		args, keywords = deserialize_params(params, method_interface)
	with server_timing("method_execution"):
		result = method(*args, **keywords)
	with server_timing("serialize_objects"):
		return serialize_result(result)


async def execute_rpc(request: JSONRPC20Request | JSONRPCRequest, backend: UnprotectedBackend | ProtectedBackend) -> Any:
	method_name = request.method

	method_interface = backend.get_method_interface(method_name)
	if not method_interface:
		logger.warning("Invalid method %r", method_name)
		raise ValueError(f"Invalid method {method_name!r}")

	if method_interface.deprecated:
		warnings.warn(f"Client {request.info.client} is calling deprecated method {method_name!r}", DeprecationWarning)
		request.info.deprecated = True

	method = getattr(backend, method_name)
	if not iscoroutinefunction(method):
		return await run_in_threadpool(execute_sync_method, method, request.params, method_interface)

	with server_timing("deserialize_objects"):
		args, keywords = await run_in_threadpool(deserialize_params, request.params, method_interface)
	with server_timing("method_execution"):
		result = await method(*args, **keywords)
	with server_timing("serialize_objects"):
		return await run_in_threadpool(serialize_result, result)


def write_debug_log(
	request: JSONRPC20Request | JSONRPCRequest | None,
	response: JSONRPC20Response | JSONRPC20ErrorResponse | JSONRPCResponse | JSONRPCErrorResponse,
	exception: Exception | None = None,
) -> None:
	now = int(time.time() * 1_000_000)
	makedirs(RPC_DEBUG_DIR, exist_ok=True)
	method = request.method if request else None
	client = request.info.client if request else None
	msg = {
		"client": client,
		"description": f"Processing request from {client} for method {method!r}",
		"request": request,
		"response": response,
		"error": str(exception) if exception else None,
	}
	prefix = re.sub(r"[\s\./]", "_", f"{client}-{now}-")
	with tempfile.NamedTemporaryFile(delete=False, dir=RPC_DEBUG_DIR, prefix=prefix, suffix=".log") as log_file:
		logger.notice("Writing rpc error log to: %s", log_file.name)
		log_file.write(msgspec.json.encode(msg))


async def process_rpc_error(
	exception: Exception, request: JSONRPC20Request | JSONRPCRequest | None = None
) -> JSONRPC20ErrorResponse | JSONRPCErrorResponse:
	_id = request.id if request else 0
	message = str(exception)
	_class = exception.__class__.__name__
	details = None
	try:
		session = contextvar_client_session.get()
		if session and session.is_admin:
			details = str(traceback.format_exc())
	except Exception as err:
		logger.warning(err, exc_info=True)

	response: JSONRPC20ErrorResponse | JSONRPCErrorResponse
	if isinstance(request, JSONRPC20Request):
		response = JSONRPC20ErrorResponse(id=_id, error=JSONRPC20Error(message=message, data={"class": _class, "details": details}))
	else:
		response = JSONRPCErrorResponse(id=_id, error={"message": message, "class": _class, "details": details})

	if "rpc-log" in config.debug_options or "rpc-error-log" in config.debug_options:
		try:
			await run_in_threadpool(write_debug_log, request, response, exception)
		except Exception as err:
			logger.warning(err, exc_info=True)

	return response


async def process_rpc(
	request: JSONRPC20Request | JSONRPCRequest, backend: ProtectedBackend | UnprotectedBackend
) -> JSONRPC20Response | JSONRPCResponse:
	logger.debug("Method '%s', params (short): %.250s", request.method, request.params)
	logger.trace("Method '%s', params (full): %s", request.method, request.params)

	result = await execute_rpc(request, backend)
	response: JSONRPC20Response | JSONRPCResponse
	if isinstance(request, JSONRPC20Request):
		response = JSONRPC20Response(id=request.id, result=result)
	else:
		response = JSONRPCResponse(id=request.id, result=result)

	if "rpc-log" in config.debug_options:
		try:
			await run_in_threadpool(write_debug_log, request, response)
		except Exception as err:
			logger.warning(err, exc_info=True)

	return response


async def process_rpcs(
	backend: ProtectedBackend | UnprotectedBackend, *requests: JSONRPC20Request | JSONRPCRequest
) -> AsyncGenerator[JSONRPC20Response | JSONRPC20ErrorResponse | JSONRPCResponse | JSONRPCErrorResponse]:
	worker = Worker.get_instance()
	metrics_collector = worker.metrics_collector
	if metrics_collector:
		await metrics_collector.add_value("worker:sum_jsonrpc_number", len(requests))

	for request in requests:
		response: JSONRPC20Response | JSONRPC20ErrorResponse | JSONRPCResponse | JSONRPCErrorResponse
		with server_timing("rpc_processing") as svt:
			try:
				logger.info(
					"JSONRPC request processing: method=%s, client=%s, worker=%d",
					request.method,
					request.info.client,
					worker.worker_num,
				)
				response = await process_rpc(request, backend)
			except Exception as err:
				logger.error(err, exc_info=True)
				response = await process_rpc_error(err, request)

		logger.trace(response)

		request.info.duration = svt["rpc_processing"] / 1000
		coro = store_rpc_info(request, response)
		if AWAIT_STORE_RPC_INFO:
			# Required for pytest
			await coro
		else:
			asyncio_create_task(coro)

		yield response


@jsonrpc_router.head("")
async def jsonrpc_head() -> Response:
	return Response()


# Some clients are using /rpc/rpc
@jsonrpc_router.get("")
@jsonrpc_router.post("")
@jsonrpc_router.get("{any:path}")
@jsonrpc_router.post("{any:path}")
async def process_request(request: Request, response: Response) -> Response:
	request_compression = None
	request_serialization = None
	response_compression = None
	response_serialization = None
	client = ""
	session = contextvar_client_session.get()
	worker = Worker.get_instance()
	metrics_collector = worker.metrics_collector
	if metrics_collector:
		await metrics_collector.add_value("worker:sum_jsonrpc_requests", 1)

	if session:
		client = f"{session.client_addr}/{session.user_agent}"
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
			raise TypeError("Request data must be bytes")
		if not request_data:
			request_data = urllib.parse.unquote(request.url.query).encode("utf-8")
			request_compression = None
		if not request_data:
			raise ValueError("Request data empty")

		inline_max_size = INLINE_MAX_REQUEST_SIZE // 4 if request_compression else INLINE_MAX_REQUEST_SIZE
		if len(request_data) <= inline_max_size:
			# Avoid thread pool overhead for small requests
			requests = decode_request(request_data, request_compression, request_serialization, client)
		else:
			requests = await run_in_threadpool(decode_request, request_data, request_compression, request_serialization, client)
		logger.trace("rpcs: %s", requests)

		backend = get_protected_backend()
		coro = process_rpcs(backend, *requests)
		results = [result async for result in coro]
		response.status_code = 200
	except HTTPException as err:
		logger.error(err)
		raise
	except Exception as err:
		logger.error(err, exc_info=True)
		results = [await process_rpc_error(err)]
		response.status_code = 400

	response_serialization = response_serialization or "json"
	response.headers["content-type"] = f"application/{response_serialization}"
	response.headers["accept"] = "application/msgpack,application/json"
	response.headers["accept-encoding"] = "lz4,gzip"
	response_data = results[0] if len(results) == 1 else results
	with server_timing("serialization"):
		if is_small_data([getattr(res, "result", None) for res in results]):
			# Avoid thread pool overhead for small responses
			data = serialize_data(response_data, response_serialization)
		else:
			data = await run_in_threadpool(serialize_data, response_data, response_serialization)

	data_len = len(data)
	if response_compression and data_len > COMPRESS_MIN_SIZE:
		response.headers["content-encoding"] = response_compression
		block_linked = True
		if request.headers.get("user-agent", "").lower().startswith(("opsi config editor", "opsi-configed")):
			# lz4-java - RuntimeException: Dependent block stream is unsupported (BLOCK_INDEPENDENCE must be set).
			block_linked = False
		with server_timing("compression"):
			if response_compression == "lz4" and data_len <= LZ4_INLINE_MAX_SIZE:
				data = compress(data, response_compression, block_linked=block_linked)
			else:
				data = await run_in_threadpool(compress, data, response_compression, block_linked=block_linked)

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

	client = f"messagebus/{message.sender}"
	if context:
		session = OPSISession.from_serialized(context)
		contextvar_client_session.set(session)
		client = f"{session.client_addr}/{session.user_agent}"

	rpc = JSONRPC20Request(info=RequestInfo(client=client), id=message.rpc_id, method=message.method, params=message.params)

	try:
		backend = get_protected_backend()
		response = await anext(process_rpcs(backend, rpc))
		cast(JSONRPC20Response, response)
	except Exception as err:
		logger.error(err, exc_info=True)
		response = await process_rpc_error(err)
		cast(JSONRPC20ErrorResponse, response)

	response_message = JSONRPCResponseMessage(
		sender=cgmr.consumer_name,
		channel=message.back_channel or message.sender,
		ref_id=message.id,
		rpc_id=str(response.id),
		result=response.result if not isinstance(response, JSONRPC20ErrorResponse) else None,
		error=response.error if isinstance(response, JSONRPC20ErrorResponse) else None,
	)

	# asyncio_create_task(send_message(response_message))
	await send_message(response_message)
	# ACK Message
	# asyncio_create_task(cgmr.ack_message(redis_id))
	await cgmr.ack_message(message.channel, redis_id)


async def messagebus_jsonrpc_request_worker_configserver() -> None:
	global jsonrpc_message_reader

	messagebus_worker_id = get_messagebus_worker_id()
	channel = f"service:depot:{get_depotserver_id()}:jsonrpc"

	# ID "0" means: Start reading pending messages (not ACKed) and continue reading new messages
	jsonrpc_message_reader = ConsumerGroupMessageReader(consumer_group=channel, consumer_name=messagebus_worker_id)
	await jsonrpc_message_reader.set_channels({channel: "0"})
	async for redis_id, message, context in jsonrpc_message_reader.get_messages():
		try:
			await _process_message(jsonrpc_message_reader, redis_id, message, context)
		except Exception as err:
			logger.error(err, exc_info=True)


async def messagebus_jsonrpc_request_worker_depotserver() -> None:
	unprotected_backend = get_unprotected_backend()
	message_queue: Queue[JSONRPCRequestMessage] = Queue()

	class JSONRPCRequestMessageListener(MessagebusListener):
		def messagebus_connection_established(self, messagebus: Messagebus) -> None:
			channel = f"service:depot:{get_depotserver_id()}:jsonrpc"
			if channel not in messagebus._subscribed_channels:
				message = ChannelSubscriptionRequestMessage(
					sender=CONNECTION_USER_CHANNEL,
					channel="service:messagebus",
					channels=[channel],
					operation="add",
				)
				logger.info("Messagebus connection established, subscribing %s", message.channels)
				messagebus.send_message(message)

		def message_received(self, message: Message) -> None:
			if isinstance(message, JSONRPCRequestMessage):
				message_queue.put(message, block=True)

	service_client = await run_in_threadpool(get_service_client, "messagebus jsonrpc", JSONRPCRequestMessageListener())

	while True:
		try:
			request: JSONRPCRequestMessage = await run_in_threadpool(message_queue.get, block=True, timeout=1.0)
		except Empty:
			continue
		rpc = JSONRPC20Request(id=request.rpc_id, method=request.method, params=request.params)
		try:
			result = await anext(process_rpcs(unprotected_backend, rpc))
		except Exception as err:
			logger.error(err, exc_info=True)
			result = await process_rpc_error(err)

		response = JSONRPCResponseMessage(
			sender=CONNECTION_USER_CHANNEL,
			channel=request.back_channel or request.sender,
			ref_id=request.id,
			rpc_id=str(result.id),
			result=result.result if isinstance(result, JSONRPC20Response) else None,
			error=result.error if isinstance(result, JSONRPC20ErrorResponse) else None,
		)
		try:
			await service_client.messagebus.async_send_message(response)
		except Exception as err:
			logger.error("Failed to send message to messagebus: %s", err)


async def messagebus_jsonrpc_request_worker() -> None:
	if get_server_role() == "configserver":
		await messagebus_jsonrpc_request_worker_configserver()
	elif get_server_role() == "depotserver":
		await messagebus_jsonrpc_request_worker_depotserver()
