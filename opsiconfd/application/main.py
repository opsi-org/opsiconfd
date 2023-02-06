# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application main
"""

import asyncio
import os
import warnings
from time import time
from ctypes import c_long
from typing import Any, AsyncGenerator
from urllib.parse import urlparse
from datetime import datetime, timezone
import msgspec
from fastapi import FastAPI, Query, status
from fastapi.exceptions import RequestValidationError
from fastapi.requests import Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.routing import APIRoute, Mount
from fastapi.staticfiles import StaticFiles
from opsicommon.logging.constants import TRACE  # type: ignore[import]
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK

from opsiconfd import __version__, contextvar_client_address, contextvar_request_id
from opsiconfd.addon import AddonManager
from opsiconfd.application import app
from opsiconfd.application.admininterface import admin_interface_setup
from opsiconfd.application.filetransfer import filetransfer_setup
from opsiconfd.application.jsonrpc import (
	async_jsonrpc_shutdown,
	async_jsonrpc_startup,
	jsonrpc_setup,
)
from opsiconfd.application.metrics import metrics_setup
from opsiconfd.application.monitoring.monitoring import monitoring_setup
from opsiconfd.application.proxy import reverse_proxy_setup
from opsiconfd.application.redisinterface import redis_interface_setup
from opsiconfd.application.session import session_setup
from opsiconfd.application.status import status_setup
from opsiconfd.application.utils import OpsiconfdWebSocketEndpoint
from opsiconfd.application.webdav import webdav_setup
from opsiconfd.backend import get_protected_backend, get_unprotected_backend
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import get_logger, logger
from opsiconfd.messagebus.terminal import (
	async_terminal_shutdown,
	async_terminal_startup,
)
from opsiconfd.messagebus.websocket import messagebus_setup
from opsiconfd.metrics.statistics import StatisticsMiddleware
from opsiconfd.redis import async_redis_client
from opsiconfd.rest import OpsiApiException, rest_api
from opsiconfd.session import SessionMiddleware
from opsiconfd.ssl import get_ca_cert_as_pem
from opsiconfd.utils import normalize_ip_address

PATH_MAPPINGS = {
	# Some WebDAV-Clients do not accept redirect on initial PROPFIND
	"/dav": "/dav/",
	"/boot": "/boot/",
	"/depot": "/depot/",
	"/public": "/public/",
	"/repository": "/repository/",
	"/workbench": "/workbench/",
}

header_logger = get_logger("opsiconfd.headers")


server_date = (0, b"")  # pylint: disable=invalid-name
def get_server_date() -> bytes:
	global server_date  # pylint: disable=global-statement,invalid-name
	now = int(time())
	if server_date[0] != now:
		server_date = (now, datetime.fromtimestamp(now, timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %Z").encode("utf-8"))
	return server_date[1]


@app.get("/")
async def index() -> RedirectResponse:
	if config.welcome_page:
		return RedirectResponse("/welcome")
	return RedirectResponse("/admin")


@app.options("/")
async def index_options() -> Response:
	# Windows WebDAV client send OPTIONS request for /
	return Response(headers={"Allow": "OPTIONS, GET, HEAD"})


@app.head("/")
async def index_head() -> Response:
	return Response()


@app.get("/login")
async def login_index(request: Request) -> Response:
	context = {
		"request": request,
	}
	return config.jinja_templates.TemplateResponse("login.html", context)


@app.get("/favicon.ico")
async def favicon(request: Request, response: Response) -> RedirectResponse:  # pylint: disable=unused-argument
	return RedirectResponse("/static/favicon.ico", status_code=status.HTTP_301_MOVED_PERMANENTLY)


@app.get("/ssl/opsi-ca-cert.pem")
def get_ssl_ca_cert(request: Request) -> Response:  # pylint: disable=unused-argument
	return Response(
		content=get_ca_cert_as_pem(),
		headers={"Content-Type": "application/x-pem-file", "Content-Disposition": 'attachment; filename="opsi-ca-cert.pem"'},
	)


@app.websocket_route("/ws/echo")
class EchoWebsocket(OpsiconfdWebSocketEndpoint):
	encoding = "bytes"
	admin_only = True

	async def on_receive(self, websocket: WebSocket, data: Any) -> None:
		await websocket.send_bytes(data)


@app.websocket_route("/ws/log_viewer")
class LoggerWebsocket(OpsiconfdWebSocketEndpoint):
	encoding = "bytes"
	admin_only = True

	def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
		super().__init__(scope, receive, send)
		self._log_reader_task: asyncio.Task
		self._last_id = "$"
		self._client: str | None = None
		self._max_message_size = 1_000_000

	async def read_data(self, data: list[list[Any]]) -> AsyncGenerator[bytes, None]:
		for stream in data:
			for dat in stream[1]:
				self._last_id = dat[0]
				if self._client and self._client != dat[1].get("client", b"").decode("utf-8"):
					continue
				yield dat[1][b"record"]

	async def _log_reader(self, websocket: WebSocket, start_id: str = "$", client: str | None = None) -> None:
		stream_name = f"{config.redis_key('log')}:{config.node_name}"
		logger.info(
			"Websocket client is starting to read log stream: stream_name=%s, start_id=%s, client=%s", stream_name, start_id, client
		)
		self._last_id = start_id
		self._client = client

		message_header = bytearray(msgspec.msgpack.encode({"type": "log-records"}))
		try:
			while True:
				if websocket.client_state != WebSocketState.CONNECTED:
					break

				redis = await async_redis_client()
				# It is also possible to specify multiple streams
				data = await redis.xread(streams={stream_name: self._last_id}, block=1000)
				if not data:
					continue
				message = message_header.copy()
				num_records = 0
				async for record in self.read_data(data):
					num_records += 1
					message += record
					if len(message) >= self._max_message_size:
						await websocket.send_bytes(message)
						message = message_header.copy()
						num_records = 0
				if num_records > 0:
					await websocket.send_bytes(message)
		except (ConnectionClosedOK, ConnectionClosedError, WebSocketDisconnect):
			pass
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

	async def on_connect(  # pylint: disable=arguments-differ
		self, websocket: WebSocket, client: str = Query(default=None), start_time: int = Query(default=0)
	) -> None:
		start_id = "$"
		if start_time > 0:
			start_id = str(start_time * 1000)
		self._log_reader_task = asyncio.get_running_loop().create_task(self._log_reader(websocket, start_id, client))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		if self._log_reader_task:
			self._log_reader_task.cancel()


class BaseMiddleware:  # pylint: disable=too-few-public-methods
	def __init__(self, app: FastAPI) -> None:  # pylint: disable=redefined-outer-name
		self.app = app

	@staticmethod
	def get_client_address(scope: Scope) -> tuple[str | None, int]:
		"""Get sanitized client address"""
		host, port = scope.get("client", (None, 0))
		if host:
			host = normalize_ip_address(host)
		return host, port

	@staticmethod
	def before_send(scope: Scope, receive: Receive, send: Send) -> None:
		pass

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		if not scope["type"] in ("http", "websocket"):
			return await self.app(scope, receive, send)

		# Generate request id and store in contextvar
		request_id = id(scope)

		# Longs on Windows are only 32 bits, but memory adresses on 64 bit python are 64 bits
		# Ensure it fits inside a long, truncating if necessary
		request_id = abs(c_long(request_id).value)
		scope["request_id"] = request_id
		contextvar_request_id.set(request_id)
		req_headers = dict(scope["headers"])

		# scope["path"] can change while processing, keep original value in scope["full_path"]
		# Wrong path will still appear in log: GET /boot/ HTTP/1.1" 200   (h11_impl.py:477)
		# Remove full_path and replace with path when the following issue is fixed:
		# https://github.com/encode/starlette/issues/1336
		scope["full_path"] = scope.get("path")
		if scope["full_path"] and (new_path := PATH_MAPPINGS.get(scope["full_path"])):
			scope["full_path"] = scope["path"] = new_path
			scope["raw_path"] = new_path.encode("utf-8")

		client_host, client_port = self.get_client_address(scope)

		if scope.get("http_version") and scope["http_version"] != "1.1":
			warnings.warn(
				f"Client {client_host!r} ({req_headers.get('user-agent', '')!r}) is using http version {scope.get('http_version')}",
				RuntimeWarning,
			)

		if client_host in config.trusted_proxies:
			proxy_host = client_host
			# from uvicorn/middleware/proxy_headers.py

			if b"x-forwarded-for" in req_headers:
				# Determine the client address from the last trusted IP in the
				# X-Forwarded-For header. We've lost the connecting client's port
				# information by now, so only include the host.
				x_forwarded_for = req_headers[b"x-forwarded-for"].decode("ascii")
				client_host = x_forwarded_for.split(",")[-1].strip()
				client_port = 0
				logger.debug("Accepting x-forwarded-for header (host=%s) from trusted proxy %s", client_host, proxy_host)

		scope["client"] = (client_host, client_port)
		contextvar_client_address.set(client_host)

		async def send_wrapper(message: Message) -> None:
			if message["type"] == "http.response.start":
				host = req_headers.get(b"host", b"localhost:4447").decode().split(":")[0]
				origin_scheme = "https"
				origin_port = 4447
				try:
					origin = urlparse(req_headers[b"origin"].decode())
					origin_scheme = origin.scheme
					origin_port = int(origin.port)
				except Exception:  # pylint: disable=broad-except
					pass

				headers = MutableHeaders(scope=message)
				headers.append("Access-Control-Allow-Origin", f"{origin_scheme}://{host}:{origin_port}")
				headers.append("Access-Control-Allow-Methods", "*")
				headers.append(
					"Access-Control-Allow-Headers",
					"Accept,Accept-Encoding,Authorization,Connection,Content-Type,Encoding,Host,Origin,X-opsi-session-lifetime,X-Requested-With",
				)
				headers.append("Access-Control-Allow-Credentials", "true")

				if header_logger.isEnabledFor(TRACE):
					header_logger.trace("<<< HTTP/%s %s %s", scope.get("http_version"), scope.get("method"), scope.get("path"))
					for header, value in req_headers.items():
						header_logger.trace(  # pylint: disable=loop-global-usage
							"<<< %s: %s", header.decode("utf-8", "replace"), value.decode("utf-8", "replace")
						)
					header_logger.trace(">>> HTTP/%s %s", scope.get("http_version"), message.get("status"))
					for header, value in dict(headers).items():
						header_logger.trace(">>> %s: %s", header, value)  # pylint: disable=loop-global-usage

			self.before_send(scope, receive, send)

			if "headers" in message:
				if (
					scope["full_path"]
					and scope["full_path"].startswith("/public/boot")
					and req_headers.get("user-agent", "").startswith("UefiHttpBoot")
				):
					# Grub 2.06 needs titled headers (Content-Length instead of content-length)
					message["headers"] = [(k.title(), v) for k, v in message["headers"] if k not in (b"date", b"server")]

				message["headers"].append((b"Date", get_server_date()))
			await send(message)

		return await self.app(scope, receive, send_wrapper)


@app.exception_handler(RequestValidationError)
@rest_api
def validation_exception_handler(request: Request, exc: Exception) -> None:
	raise OpsiApiException(message=f"Validation error: {exc}", http_status=status.HTTP_422_UNPROCESSABLE_ENTITY, error=exc)


def application_setup() -> None:
	if app.application_setup_done:
		return
	app.application_setup_done = True
	# Create Backend instance
	get_unprotected_backend()
	get_protected_backend()

	FileResponse.chunk_size = 32 * 1024  # Speeds up transfer of big files massively, original value is 4*1024

	# Every Starlette application automatically includes two pieces of middleware by default:
	#    ServerErrorMiddleware: Ensures that application exceptions may return a custom 500 page,
	#                           or display an application traceback in DEBUG mode.
	#                           This is always the outermost middleware layer.
	#      ExceptionMiddleware: Adds exception handlers, so that particular types of expected
	#                           exception cases can be associated with handler functions.
	#                           For example raising HTTPException(status_code=404) within an endpoint
	#                           will end up rendering a custom 404 page.
	#
	# Last added middleware will be executed first
	# middleware stack:
	#    ServerErrorMiddleware
	#    user added middlewares
	#    ExceptionMiddleware
	#
	# Exceptions raised from user middleware will not be catched by ExceptionMiddleware
	app.add_middleware(
		SessionMiddleware,
		public_path=[
			"/dav/public",
			"/favicon.ico",
			"/login",
			"/metrics/grafana",
			"/public",
			"/session/login",
			"/session/logout",
			"/ssl/opsi-ca-cert.pem",
			"/status",
			"/static",
			"/welcome",
		],
	)
	# app.add_middleware(GZipMiddleware, minimum_size=1000)
	app.add_middleware(StatisticsMiddleware, profiler_enabled=config.profiler, log_func_stats=config.profiler)
	app.add_middleware(BaseMiddleware)
	if os.path.isdir(config.static_dir):
		app.mount("/static", StaticFiles(directory=config.static_dir), name="static")
	else:
		logger.warning("Static dir '%s' not found", config.static_dir)

	jsonrpc_setup(app)
	session_setup(app)
	admin_interface_setup(app)
	redis_interface_setup(app)
	webdav_setup(app)
	filetransfer_setup(app)
	status_setup(app)

	if opsi_config.get("host", "server-role") == "configserver":
		monitoring_setup(app)
		metrics_setup(app)
		messagebus_setup(app)
		reverse_proxy_setup(app)

	AddonManager().load_addons()

	logger.debug("Routing:")
	routes = {}
	for route in app.routes:  # pylint: disable=use-dict-comprehension
		if isinstance(route, Mount):
			routes[route.path] = str(route.app.__module__)
		elif isinstance(route, APIRoute):
			module = route.endpoint.__module__
			if module.startswith("opsiconfd.addon_"):
				module = f"opsiconfd.addon.{module.split('/')[-1]}"
			routes[route.path] = f"{module}.{route.endpoint.__qualname__}"
		elif hasattr(route, "path"):
			routes[getattr(route, "path", "")] = route.__class__.__name__
	for path in sorted(routes):
		logger.debug("%s: %s", path, routes[path])


def application_startup() -> None:
	application_setup()


def application_shutdown() -> None:
	get_unprotected_backend().shutdown()
	get_protected_backend().shutdown()


async def async_application_startup() -> None:
	# Create redis pool
	await async_redis_client(timeout=10, test_connection=True)

	await async_jsonrpc_startup()
	await async_terminal_startup()


async def async_application_shutdown() -> None:
	await async_jsonrpc_shutdown()
	await async_terminal_shutdown()


@app.on_event("startup")
async def startup() -> None:
	try:
		await run_in_threadpool(application_startup)
		await async_application_startup()
	except Exception as error:  # pylint: disable=broad-except
		logger.critical("Error during application startup: %s", error, exc_info=True)
		raise error


@app.on_event("shutdown")
async def shutdown() -> None:
	logger.info("Processing shutdown event")
	try:
		await run_in_threadpool(application_shutdown)
		await async_application_shutdown()
	except Exception as error:  # pylint: disable=broad-except
		logger.critical("Error during application shutdown: %s", error, exc_info=True)
