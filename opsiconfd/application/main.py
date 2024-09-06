# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
application main
"""

import asyncio
import os
from typing import Any, AsyncGenerator

import msgspec
from fastapi import status
from fastapi.exceptions import RequestValidationError
from fastapi.requests import Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.routing import APIRoute, Mount
from fastapi.staticfiles import StaticFiles
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

from opsiconfd.addon import AddonManager
from opsiconfd.application import app
from opsiconfd.application.admininterface import admin_interface_setup
from opsiconfd.application.auth import auth_setup
from opsiconfd.application.filetransfer import filetransfer_setup
from opsiconfd.application.jsonrpc import (
	async_jsonrpc_shutdown,
	async_jsonrpc_startup,
	jsonrpc_setup,
)
from opsiconfd.application.metrics import metrics_setup
from opsiconfd.application.middleware import BaseMiddleware
from opsiconfd.application.monitoring.monitoring import monitoring_setup
from opsiconfd.application.proxy import reverse_proxy_setup
from opsiconfd.application.redisinterface import redis_interface_setup
from opsiconfd.application.status import status_setup
from opsiconfd.application.utils import OpsiconfdWebSocketEndpoint
from opsiconfd.application.webdav import webdav_setup
from opsiconfd.backend import get_protected_backend, get_unprotected_backend
from opsiconfd.config import config, get_server_role, jinja_templates
from opsiconfd.logging import logger
from opsiconfd.messagebus.file_transfer import async_file_transfer_shutdown
from opsiconfd.messagebus.process import async_process_shutdown, async_process_startup
from opsiconfd.messagebus.terminal import async_terminal_shutdown, async_terminal_startup
from opsiconfd.messagebus.websocket import messagebus_setup
from opsiconfd.metrics.statistics import StatisticsMiddleware
from opsiconfd.redis import async_redis_client
from opsiconfd.rest import OpsiApiException, rest_api
from opsiconfd.session import SessionMiddleware, session_manager
from opsiconfd.ssl import get_ca_certs_as_pem, get_opsi_ca_cert_as_pem
from opsiconfd.utils import asyncio_create_task


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
@app.post("/login")
async def login_index(request: Request) -> Response:
	context = {"request": request, "multi_factor_auth": config.multi_factor_auth, "saml_login_enabled": bool(config.saml_idp_sso_url)}
	return jinja_templates().TemplateResponse(request=request, name="login.html", context=context)


@app.get("/favicon.ico")
async def favicon(request: Request, response: Response) -> RedirectResponse:
	return RedirectResponse("/static/favicon.ico", status_code=status.HTTP_301_MOVED_PERMANENTLY)


@app.get("/ssl/opsi-ca-cert.pem")
def get_ssl_ca_cert(request: Request) -> Response:
	return Response(
		content=get_opsi_ca_cert_as_pem(),
		headers={"Content-Type": "application/x-pem-file", "Content-Disposition": 'attachment; filename="opsi-ca-cert.pem"'},
	)


@app.get("/ssl/ca-certs.pem")
def get_ca_certs(request: Request) -> Response:
	return Response(
		content=get_ca_certs_as_pem(),
		headers={"Content-Type": "application/x-pem-file", "Content-Disposition": 'attachment; filename="ca-certs.pem"'},
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
		except WebSocketDisconnect:
			pass
		except Exception as err:
			logger.error(err, exc_info=True)

	async def on_connect(self, websocket: WebSocket, client: str | None = None, start_time: str | int | None = None) -> None:
		start_id = "$"
		try:
			start_time = int(start_time or 0)
		except (ValueError, TypeError):
			start_time = 0
		if start_time > 0:
			start_id = str(start_time * 1000)
		self._log_reader_task = asyncio.create_task(self._log_reader(websocket, start_id, client))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		if self._log_reader_task:
			self._log_reader_task.cancel()


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

	jsonrpc_setup(app)
	auth_setup(app)
	admin_interface_setup(app)
	redis_interface_setup(app)
	webdav_setup(app)
	filetransfer_setup(app)
	status_setup(app)

	if get_server_role() == "configserver":
		monitoring_setup(app)
		metrics_setup(app)
		messagebus_setup(app)
		reverse_proxy_setup(app)

	AddonManager().load_addons()

	logger.debug("Routing:")
	routes = {}
	for route in app.routes:
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

	session_manager.reset()
	asyncio_create_task(session_manager.manager_task())
	await async_jsonrpc_startup()
	await async_terminal_startup()
	await async_process_startup()


async def async_application_shutdown() -> None:
	await async_jsonrpc_shutdown()
	await async_terminal_shutdown()
	await async_process_shutdown()
	await async_file_transfer_shutdown()
	await session_manager.stop()


def setup_app() -> None:
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

	public_path = [
		"/favicon.ico",
		"/login",
		"/auth/wait_authenticated",
		"/auth/login",
		"/auth/logout",
		"/auth/session_id",
		"/auth/saml",
		"/ssl/opsi-ca-cert.pem",
		"/ssl/ca-certs.pem",
		"/static",
		"/welcome",
	]
	if "status-page" not in config.disabled_features:
		public_path.append("/status")
	if "public-folder" not in config.disabled_features:
		public_path.extend(["/public", "/dav/public"])

	app.add_middleware(SessionMiddleware, public_path=public_path)
	# app.add_middleware(GZipMiddleware, minimum_size=1000)
	app.add_middleware(StatisticsMiddleware)
	app.add_middleware(BaseMiddleware)
	if os.path.isdir(config.static_dir):
		app.mount("/static", StaticFiles(directory=config.static_dir), name="static")
	else:
		logger.warning("Static dir '%s' not found", config.static_dir)
