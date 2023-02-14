# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
jsonrpc
"""

from __future__ import annotations

import asyncio
import re
import tempfile
import time
import traceback
import urllib.parse
import warnings
from datetime import datetime
from os import makedirs
from queue import Empty, Queue
from typing import TYPE_CHECKING, Any, AsyncGenerator, Optional

import msgspec
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.requests import Request
from fastapi.responses import Response
from opsicommon.client.opsiservice import MessagebusListener
from opsicommon.messagebus import (  # type: ignore[import]
	ChannelSubscriptionRequestMessage,
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	Message,
)
from opsicommon.objects import deserialize, serialize  # type: ignore[import]
from starlette.concurrency import run_in_threadpool

from opsiconfd import contextvar_client_session, server_timing
from opsiconfd.backend import (
	get_protected_backend,
	get_service_client,
	get_unprotected_backend,
)
from opsiconfd.config import RPC_DEBUG_DIR, config, get_depotserver_id, opsi_config
from opsiconfd.logging import logger
from opsiconfd.messagebus import get_user_id_for_service_worker
from opsiconfd.messagebus.redis import ConsumerGroupMessageReader, send_message
from opsiconfd.redis import async_redis_client
from opsiconfd.session import OPSISession
from opsiconfd.utils import compress_data, decompress_data
from opsiconfd.worker import Worker

if TYPE_CHECKING:
	from opsiconfd.backend.rpc.main import ProtectedBackend, UnprotectedBackend


COMPRESS_MIN_SIZE = 10000
AWAIT_STORE_RPC_INFO = False

jsonrpc_router = APIRouter()
jsonrpc_message_reader = None  # pylint: disable=invalid-name


def jsonrpc_setup(app: FastAPI) -> None:
	app.include_router(jsonrpc_router, prefix="/rpc")


async def async_jsonrpc_startup() -> None:
	asyncio.create_task(messagebus_jsonrpc_request_worker())


async def async_jsonrpc_shutdown() -> None:
	if jsonrpc_message_reader:
		await jsonrpc_message_reader.stop()


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
		return json_encoder.encode(data)
	raise ValueError(f"Unhandled serialization {serialization!r}")


async def store_rpc_info(  # pylint: disable=too-many-locals
	rpc: Any, result: dict[str, Any], duration: float, date: datetime, client_info: str
) -> None:
	is_error = bool(result.get("error"))
	worker = Worker.get_instance()
	metrics_collector = worker.metrics_collector
	if metrics_collector and not is_error:
		await metrics_collector.add_value(
			"worker:avg_jsonrpc_duration", duration, {"node_name": config.node_name, "worker_num": worker.worker_num}
		)

	redis = await async_redis_client()
	rpc_num = await redis.incr(f"{config.redis_key('stats')}:num_rpcs")

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
		worker.worker_num,
	)

	max_rpcs = 9999
	redis_prefix_stats = config.redis_key("stats")
	async with redis.pipeline() as pipe:
		pipe.lpush(f"{redis_prefix_stats}:rpcs", msgspec.msgpack.encode(data))  # pylint: disable=c-extension-no-member
		pipe.ltrim(f"{redis_prefix_stats}:rpcs", 0, max_rpcs - 1)
		await pipe.execute()


async def store_deprecated_call(method_name: str, client: str) -> None:
	redis_prefix_stats = config.redis_key("stats")
	redis = await async_redis_client()
	async with redis.pipeline() as pipe:
		pipe.sadd(f"{redis_prefix_stats}:rpcs:deprecated:methods", method_name)
		pipe.incr(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:count")
		pipe.sadd(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:clients", client[client.index("/") + 1 :])
		pipe.set(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:last_call", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
		await pipe.execute()


async def execute_rpc(client_info: str, rpc: dict[str, Any], backend: UnprotectedBackend | ProtectedBackend) -> Any:
	method_name = rpc["method"]
	params = rpc["params"]

	method_interface = backend.get_method_interface(method_name)
	if not method_interface:
		logger.warning("Invalid method %r", method_name)
		raise ValueError(f"Invalid method {method_name!r}")

	with server_timing("deserialize_objects"):
		keywords = {}
		if isinstance(params, dict):
			keywords = await run_in_threadpool(deserialize, params)
			params = []
		else:
			if method_interface.keywords:
				parameter_count = 0
				if method_interface.args:
					parameter_count += len(method_interface.args)
				if method_interface.varargs:
					parameter_count += len(method_interface.varargs)

				if len(params) >= parameter_count:
					# params needs to be a copy, leave rpc["params"] unchanged
					kwargs = params[-1]
					params = params[:-1]
					if not isinstance(kwargs, dict):
						raise TypeError(f"kwargs param is not a dict: {type(kwargs)}")
					keywords = {str(key): await run_in_threadpool(deserialize, value) for key, value in kwargs.items()}
			params = await run_in_threadpool(deserialize, params)

	method = getattr(backend, method_name)
	if method.rpc_interface.deprecated:
		warnings.warn(f"Client {client_info} is calling deprecated method {method_name!r}", DeprecationWarning)
		await store_deprecated_call(method_name, client_info)

	with server_timing("method_execution"):
		if asyncio.iscoroutinefunction(method):
			result = await method(*params, **keywords)
		else:
			result = await run_in_threadpool(method, *params, **keywords)

	with server_timing("serialize_objects"):
		return await run_in_threadpool(serialize, result)


def write_debug_log(
	client_info: str, request: dict[str, Any] | None = None, response: Any = None, exception: Exception | None = None
) -> None:
	now = int(time.time() * 1_000_000)
	makedirs(RPC_DEBUG_DIR, exist_ok=True)
	method = request.get("method") if request else None
	msg = {
		"client": client_info,
		"description": f"Processing request from {client_info} for method {method!r}",
		"request": request,
		"response": response,
		"error": str(exception) if exception else None,
	}
	prefix = re.sub(r"[\s\./]", "_", f"{client_info}-{now}-")
	with tempfile.NamedTemporaryFile(delete=False, dir=RPC_DEBUG_DIR, prefix=prefix, suffix=".log") as log_file:
		logger.notice("Writing rpc error log to: %s", log_file.name)
		log_file.write(msgspec.json.encode(msg))  # pylint: disable=no-member


async def process_rpc_error(client_info: str, exception: Exception, rpc: dict[str, Any] | None = None) -> Any:
	_id = rpc.get("id") if rpc else None
	message = str(exception)
	_class = exception.__class__.__name__
	details = None
	try:
		session = contextvar_client_session.get()
		if session and session.is_admin:
			details = str(traceback.format_exc())
	except Exception as err:  # pylint: disable=broad-except
		logger.warning(err, exc_info=True)

	if rpc and rpc.get("jsonrpc") == "2.0":
		response = {
			"jsonrpc": "2.0",
			"id": _id,
			"error": {"code": 0, "message": message, "data": {"class": _class, "details": details}},  # TODO
		}
	else:
		response = {"id": 0 if _id is None else _id, "result": None, "error": {"message": message, "class": _class, "details": details}}

	if "rpc-log" in config.debug_options or "rpc-error-log" in config.debug_options:
		try:
			await run_in_threadpool(write_debug_log, client_info, rpc, response, exception)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err, exc_info=True)

	return response


async def process_rpc(client_info: str, rpc: dict[str, Any], backend: ProtectedBackend | UnprotectedBackend) -> dict[str, Any]:
	if "id" not in rpc:
		rpc["id"] = 0
	if "params" not in rpc:
		rpc["params"] = []
	if "method" not in rpc:
		raise ValueError("Key 'method' missing in rpc")

	logger.debug("Method '%s', params (short): %.250s", rpc["method"], rpc["params"])
	logger.trace("Method '%s', params (full): %s", rpc["method"], rpc["params"])

	result = await execute_rpc(client_info, rpc, backend)
	if rpc.get("jsonrpc") == "2.0":
		response = {"jsonrpc": "2.0", "id": rpc["id"], "result": result}
	else:
		response = {"id": rpc["id"], "result": result, "error": None}

	if "rpc-log" in config.debug_options:
		try:
			await run_in_threadpool(write_debug_log, client_info, rpc, response, None)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err, exc_info=True)

	return response


async def process_rpcs(
	backend: ProtectedBackend | UnprotectedBackend, client_info: str, *rpcs: dict[str, Any]
) -> AsyncGenerator[dict[str, Any], None]:
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
			try:
				logger.debug("Processing request from %s for %s", client_info, rpc["method"])
				result = await process_rpc(client_info, rpc, backend)
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
				result = await process_rpc_error(client_info, err, rpc)

		logger.trace(result)

		duration = svt["rpc_processing"] / 1000
		coro = store_rpc_info(rpc, result, duration, date, client_info)
		if AWAIT_STORE_RPC_INFO:
			# Required for pytest
			await coro
		else:
			asyncio.create_task(coro)

		yield result


@jsonrpc_router.head("")
async def jsonrpc_head() -> Response:
	return Response()


# Some clients are using /rpc/rpc
@jsonrpc_router.get("")
@jsonrpc_router.post("")
@jsonrpc_router.get("{any:path}")
@jsonrpc_router.post("{any:path}")
async def process_request(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	request: Request, response: Response
) -> Response:
	request_compression = None
	request_serialization = None
	response_compression = None
	response_serialization = None
	client_info = ""
	session = contextvar_client_session.get()
	if session:
		client_info = f"{session.client_addr}/{session.user_agent}"
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

		backend = get_protected_backend()
		if isinstance(rpcs, list):
			coro = process_rpcs(backend, client_info, *rpcs)
		else:
			coro = process_rpcs(backend, client_info, rpcs)
		results = [result async for result in coro]
		response.status_code = 200
	except HTTPException as err:  # pylint: disable=broad-except
		logger.error(err)
		raise
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		results = [await process_rpc_error(client_info, err)]
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

	client_info = f"messagebus/{message.sender}"
	if context:
		session = OPSISession.from_serialized(context)
		contextvar_client_session.set(session)
		client_info = f"{session.client_addr}/{session.user_agent}"

	rpc = {"jsonrpc": "2.0", "id": message.rpc_id, "method": message.method, "params": message.params}

	try:
		backend = get_protected_backend()
		result = await anext(process_rpcs(backend, client_info, rpc))
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		result = await process_rpc_error(client_info, err)

	response_message = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
		sender=cgmr.consumer_name,
		channel=message.back_channel or message.sender,
		ref_id=message.id,
		rpc_id=result["id"],
		result=result.get("result"),
		error=result.get("error"),
	)

	# asyncio.create_task(send_message(response_message))
	await send_message(response_message)
	# ACK Message
	# asyncio.create_task(cgmr.ack_message(redis_id))
	await cgmr.ack_message(message.channel, redis_id)


async def messagebus_jsonrpc_request_worker_configserver() -> None:
	global jsonrpc_message_reader  # pylint: disable=invalid-name,global-statement

	worker = Worker.get_instance()
	messagebus_worker_id = get_user_id_for_service_worker(worker.id)
	channel = "service:config:jsonrpc"

	jsonrpc_message_reader = ConsumerGroupMessageReader(consumer_group=channel, consumer_name=messagebus_worker_id, channels={channel: "0"})
	async for redis_id, message, context in jsonrpc_message_reader.get_messages():
		try:
			await _process_message(jsonrpc_message_reader, redis_id, message, context)
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)


async def messagebus_jsonrpc_request_worker_depotserver() -> None:
	unprotected_backend = get_unprotected_backend()
	depot_id = get_depotserver_id()
	service_client = await run_in_threadpool(get_service_client, "messagebus jsonrpc")
	message = ChannelSubscriptionRequestMessage(
		sender="@", channel="service:messagebus", channels=[f"service:depot:{depot_id}:jsonrpc"], operation="add"
	)
	await run_in_threadpool(service_client.messagebus.send_message, message)

	message_queue: Queue[JSONRPCRequestMessage] = Queue()

	class JSONRPCRequestMessageListener(MessagebusListener):
		def message_received(self, message: Message) -> None:
			if isinstance(message, JSONRPCRequestMessage):
				message_queue.put(message, block=True)

	listener = JSONRPCRequestMessageListener()

	service_client.messagebus.register_messagebus_listener(listener)
	client_info = "none"
	while True:
		try:
			request: JSONRPCRequestMessage = await run_in_threadpool(message_queue.get, block=True, timeout=1.0)
		except Empty:
			continue
		rpc = {"jsonrpc": "2.0", "id": request.rpc_id, "method": request.method, "params": request.params}

		try:
			result = await anext(process_rpcs(unprotected_backend, client_info, rpc))
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
			result = await process_rpc_error(client_info, err)

		response = JSONRPCResponseMessage(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
			sender="@",
			channel=request.back_channel or request.sender,
			ref_id=request.id,
			rpc_id=result["id"],
			result=result.get("result"),
			error=result.get("error"),
		)
		await run_in_threadpool(service_client.messagebus.send_message, response)


async def messagebus_jsonrpc_request_worker() -> None:
	if opsi_config.get("host", "server-role") == "configserver":
		await messagebus_jsonrpc_request_worker_configserver()
	elif opsi_config.get("host", "server-role") == "depotserver":
		await messagebus_jsonrpc_request_worker_depotserver()
