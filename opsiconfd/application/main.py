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
from fastapi import FastAPI
import urllib

from starlette.endpoints import WebSocketEndpoint
from starlette.websockets import WebSocket
from websockets.exceptions import ConnectionClosedOK
from fastapi.staticfiles import StaticFiles
from fastapi.requests import Request
from fastapi.responses import Response, HTMLResponse, FileResponse, RedirectResponse
from fastapi.middleware.gzip import GZipMiddleware

from ..logging import init_logging, logger
from ..config import config
from ..worker import get_redis_client, init_worker
from ..session import SessionMiddleware
from ..statistics import StatisticsMiddleware
from .metrics import metrics_setup
from .jsonrpc import jsonrpc_setup
from .webdav import webdav_setup

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
				data = await self._redis.xread(block=1000, **{stream_name: last_id})
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
		self._redis = await get_redis_client()
		await asyncio.create_task(self._reader(start_id, client))
	
	async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
		pass


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, response: Response):
	return RedirectResponse("/static/index.html", status_code=301)

@app.on_event("startup")
async def startup_event():
	app.is_shutting_down = False
	init_worker()
	application_setup()

@app.on_event("shutdown")
async def shutdown_event():
	app.is_shutting_down = True

def application_setup():
	FileResponse.chunk_size = 32*1024 # speeds up transfer of big files massively, original value is 4*1024

	# Last added middleware will be executed first
	app.add_middleware(SessionMiddleware, public_path=["/boot"])
	#app.add_middleware(GZipMiddleware, minimum_size=1000)
	app.add_middleware(StatisticsMiddleware, profiler_enabled=config.profiler, log_func_stats=config.profiler)

	app.mount("/static", StaticFiles(directory="static"), name="static")
	# Exporting /tftpboot via webdav currently
	#if os.path.isdir("/tftpboot"):
	#	app.mount("/boot", StaticFiles(directory="/tftpboot"), name="boot")
	jsonrpc_setup(app)
	webdav_setup(app)
	metrics_setup(app)
