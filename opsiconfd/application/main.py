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

import os
import asyncio
import urllib
import datetime
from ctypes import c_long

from starlette.endpoints import WebSocketEndpoint
from starlette.websockets import WebSocket
from starlette.types import ASGIApp
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.requests import Request
from fastapi.responses import Response, HTMLResponse, FileResponse, RedirectResponse, StreamingResponse
from websockets.exceptions import ConnectionClosedOK

from .. import contextvar_request_id, contextvar_client_address
from ..logging import logger
from ..config import config
from ..worker import get_redis_client, init_worker
from ..session import SessionMiddleware
from ..statistics import StatisticsMiddleware
from ..utils import normalize_ip_address
from ..ssl import get_ca_cert_as_pem
from .metrics import metrics_setup
from .jsonrpc import jsonrpc_setup
from .webdav import webdav_setup
from .jsonrpcinterface import jsonrpc_interface_setup
from .admininterface import admin_interface_setup
from .redisinterface import redis_interface_setup
from .monitoring.monitoring import monitoring_setup

app = FastAPI()

@app.websocket_route("/ws/log_viewer")
class LoggerWebsocket(WebSocketEndpoint):
	encoding = 'bytes'

	async def _reader(self, start_id='$', client=None):
		stream_name = "opsiconfd:log"
		logger.info("Websocket client is starting to read log stream: stream_name=%s, start_id=%s, client=%s", stream_name, start_id, client)
		b_stream_name = stream_name.encode("utf-8")
		last_id = start_id
		while True:
			try:
				# It is also possible to specify multiple streams
				redis_client = await get_redis_client()
				data = await redis_client.xread(block=1000, **{stream_name: last_id})
				if not data:
					continue
				buf = b""
				for dat in data[b_stream_name]:
					last_id = dat[0]
					if client and client !=	dat[1].get("client", b'').decode("utf-8"):
						continue
					buf += dat[1][b"record"]
				await self._websocket.send_text(buf)
			except Exception as err:  # pylint: disable=broad-except
				if not app.is_shutting_down and not isinstance(err, ConnectionClosedOK):
					logger.error(err, exc_info=True)
				break

	async def on_connect(self, websocket: WebSocket):
		self._websocket = websocket  # pylint: disable=attribute-defined-outside-init
		params = urllib.parse.parse_qs(websocket.get('query_string', b'').decode('utf-8'))
		client = params.get("client", [None])[0]
		start_id = int(params.get("start_time", [0])[0]) * 1000 # Seconds to millis
		if start_id <= 0:
			start_id = "$"
		await self._websocket.accept()
		await asyncio.get_event_loop().create_task(self._reader(str(start_id), client))

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		pass

@app.websocket_route("/test/ws")
class TestWebsocket(WebSocketEndpoint):
	encoding = 'bytes'

	async def on_connect(self, websocket: WebSocket):
		#params = urllib.parse.parse_qs(websocket.get('query_string', b'').decode('utf-8'))
		#client = params.get("client", [None])[0]
		await websocket.accept()
		while True:
			current_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
			text = f"current utc time: {current_time}"
			logger.info("Sending '%s'", text)
			await websocket.send_text(text)
			await asyncio.sleep(10)

	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		pass

@app.get("/test/random-data")
async def get_test_random(request: Request):  # pylint: disable=unused-argument
	random = open("/dev/urandom", mode="rb")
	return StreamingResponse(random, media_type="application/binary")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, response: Response):  # pylint: disable=unused-argument
	return RedirectResponse("/admin", status_code=301)

@app.on_event("startup")
async def startup_event():
	app.is_shutting_down = False
	try:
		init_worker()
		application_setup()
	except Exception as error:
		logger.critical("Error during worker startup: %s", error, exc_info=True)
		raise error

@app.on_event("shutdown")
async def shutdown_event():
	app.is_shutting_down = True

@app.get("/ssl/opsi-ca-cert.pem")
def get_ssl_ca_cert(request: Request):  # pylint: disable=unused-argument
	return Response(
		content=get_ca_cert_as_pem(),
		headers={
			"Content-Type": "application/x-pem-file",
			"Content-Disposition": 'attachment; filename="opsi-ca-cert.pem"'
		}
	)


class BaseMiddleware:  # pylint: disable=too-few-public-methods
	def __init__(self, app: ASGIApp) -> None:  # pylint: disable=redefined-outer-name
		self.app = app

	async def __call__(self, scope, receive, send):
		if scope["type"] in ("http", "websocket"):
			# Generate request id and store in contextvar
			request_id = id(scope)
			# Longs on Windows are only 32 bits, but memory adresses on 64 bit python are 64 bits
			# Ensure it fits inside a long, truncating if necessary
			request_id = abs(c_long(request_id).value)
			scope["request_id"] = request_id
			contextvar_request_id.set(request_id)

			# Sanitize client address
			client_addr = scope.get("client")
			client_host = client_addr[0] if client_addr else None
			client_port = client_addr[1] if client_addr else 0

			if client_host in config.trusted_proxies:
				proxy_host = normalize_ip_address(client_host)
				# from uvicorn/middleware/proxy_headers.py
				headers = dict(scope["headers"])
				#if b"x-forwarded-proto" in headers:
				#	# Determine if the incoming request was http or https based on
				#	# the X-Forwarded-Proto header.
				#	x_forwarded_proto = headers[b"x-forwarded-proto"].decode("ascii")
				#	scope["scheme"] = x_forwarded_proto.strip()

				if b"x-forwarded-for" in headers:
					# Determine the client address from the last trusted IP in the
					# X-Forwarded-For header. We've lost the connecting client's port
					# information by now, so only include the host.
					x_forwarded_for = headers[b"x-forwarded-for"].decode("ascii")
					client_host = x_forwarded_for.split(",")[-1].strip()
					client_port = 0
					logger.debug(
						"Accepting x-forwarded-for header (host=%s) from trusted proxy %s",
						client_host, proxy_host
					)

			if client_host:
				# Normalize ip address
				client_host = normalize_ip_address(client_host)
			scope["client"] = (client_host, client_port)
			contextvar_client_address.set(client_host)

		return await self.app(scope, receive, send)

def application_setup():
	FileResponse.chunk_size = 32*1024 # speeds up transfer of big files massively, original value is 4*1024

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
	app.add_middleware(SessionMiddleware, public_path=["/boot", "/metrics/grafana", "/ws/test", "/ssl/opsi-ca-cert.pem"])
	#app.add_middleware(GZipMiddleware, minimum_size=1000)
	app.add_middleware(StatisticsMiddleware, profiler_enabled=config.profiler, log_func_stats=config.profiler)
	app.add_middleware(BaseMiddleware)
	if os.path.isdir(config.static_dir):
		app.mount("/static", StaticFiles(directory=config.static_dir), name="static")
	else:
		logger.warning("Static dir '%s' not found", config.static_dir)
	# Exporting /tftpboot via webdav currently
	#if os.path.isdir("/tftpboot"):
	#	app.mount("/boot", StaticFiles(directory="/tftpboot"), name="boot")
	jsonrpc_setup(app)
	jsonrpc_interface_setup(app)
	admin_interface_setup(app)
	redis_interface_setup(app)
	monitoring_setup(app)
	webdav_setup(app)
	metrics_setup(app)

