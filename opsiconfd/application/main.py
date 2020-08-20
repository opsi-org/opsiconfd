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

from starlette.endpoints import WebSocketEndpoint
from starlette.websockets import WebSocket
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.requests import Request
from fastapi.responses import Response, HTMLResponse, FileResponse, RedirectResponse
from websockets.exceptions import ConnectionClosedOK

from ..logging import logger
from ..config import config
from ..worker import get_redis_client, init_worker
from ..session import SessionMiddleware
from ..statistics import StatisticsMiddleware
from .metrics import metrics_setup
from .jsonrpc import jsonrpc_setup
from .webdav import webdav_setup
from .jsonrpcinterface import jsonrpc_interface_setup
from .admininterface import admin_interface_setup
from .redisinterface import redis_interface_setup

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
			except Exception as exc:
				if not app.is_shutting_down and not isinstance(exc, ConnectionClosedOK):
					logger.error(exc, exc_info=True)
				break

	async def on_connect(self, websocket: WebSocket):
		self._websocket = websocket
		params = urllib.parse.parse_qs(websocket.get('query_string', b'').decode('utf-8'))
		client = params.get("client", [None])[0]
		start_id = params.get("start_time", ["$"])[0]
		await self._websocket.accept()
		await asyncio.get_event_loop().create_task(self._reader(start_id, client))
	
	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		pass

@app.websocket_route("/ws/test")
class TestWebsocket(WebSocketEndpoint):
	encoding = 'bytes'

	async def on_connect(self, websocket: WebSocket):
		#params = urllib.parse.parse_qs(websocket.get('query_string', b'').decode('utf-8'))
		#client = params.get("client", [None])[0]
		await websocket.accept()
		while True:
			ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
			text = f"current utc time: {ts}"
			logger.info("Sending '%s'", text)
			await websocket.send_text(text)
			await asyncio.sleep(10)
	
	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		pass

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, response: Response):
	return RedirectResponse("/admin", status_code=301)

@app.on_event("startup")
async def startup_event():
	app.is_shutting_down = False
	init_worker()
	application_setup()

@app.on_event("shutdown")
async def shutdown_event():
	app.is_shutting_down = True

#@app.exception_handler(StarletteHTTPException)
#async def http_exception_handler(request, exc):
#    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
"""
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exception: Exception):
	print("==============================exception_handler=====================================")
	return PlainTextResponse(str(exception.detail), status_code=exception.status_code)
	#return Response(content=str(exception), status_code=500, media_type='application/json')
	#return JSONResponse(content={'error': str(exception)}, status_code=500)
	#return JSONResponse(content={'error': str(exception)}, status_code=200)

def http_exception(self, request: Request, exc: HTTPException) -> Response:
	print("==============================http_exception=====================================")
	if exc.status_code in {204, 304}:
		return Response(b"", status_code=exc.status_code)
	return PlainTextResponse(exc.detail, status_code=exc.status_code)

def error_response(self, request: Request, exc: Exception) -> Response:
	print("==============================error_response=====================================")
	return PlainTextResponse("Internal Server Error", status_code=500)
"""


def application_setup():
	FileResponse.chunk_size = 32*1024 # speeds up transfer of big files massively, original value is 4*1024

	# Every Starlette application automatically includes two pieces of middleware by default:
	#    ServerErrorMiddleware - Ensures that application exceptions may return a custom 500 page, or display an application traceback in DEBUG mode. This is always the outermost middleware layer.
	#    ExceptionMiddleware - Adds exception handlers, so that particular types of expected exception cases can be associated with handler functions. For example raising HTTPException(status_code=404) within an endpoint will end up rendering a custom 404 page.
	# Last added middleware will be executed first
	# middleware stack:
	#    ServerErrorMiddleware 
	#    user added middlewares
	#    ExceptionMiddleware
	#
	# Exceptions raised from user middleware will not be catched by ExceptionMiddleware
	app.add_middleware(SessionMiddleware, public_path=["/boot", "/metrics/grafana", "/ws/test"])
	#app.add_middleware(GZipMiddleware, minimum_size=1000)
	app.add_middleware(StatisticsMiddleware, profiler_enabled=config.profiler, log_func_stats=config.profiler)
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
	webdav_setup(app)
	metrics_setup(app)

