# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
messagebroker
"""

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, Query, FastAPI
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocket
from websockets.exceptions import ConnectionClosedOK

from .. import contextvar_client_session
from ..logging import logger
from ..utils import async_redis_client


messagebroker_router = APIRouter()
_app: Optional[FastAPI] = None  # pylint: disable=invalid-name


def messagebroker_setup(app):
	global _app  # pylint: disable=invalid-name,global-statement
	_app = app
	app.include_router(messagebroker_router, prefix="/mq")


def mq_websocket_parameters(last_id: Optional[str] = Query(default="0", embed=True)):
	return {"last_id": last_id}


async def mq_websocket_writer(websocket: WebSocket, channel: str, last_id: str = "0"):
	def read_data(data, channel):
		b_channel = channel.encode("utf-8")
		buf = bytearray()
		for dat in data[b_channel]:
			last_id = dat[0]
			buf += dat[1]  # [b"record"]
		return (last_id, buf)

	redis = await async_redis_client()
	while True:
		try:
			# redis = await async_redis_client()
			# It is also possible to specify multiple streams
			data = await redis.xread(streams={channel: last_id}, block=1000, count=10)
			if not data:
				continue
			last_id, buf = await run_in_threadpool(read_data, data, channel)
			await websocket.send_bytes(buf)
		except Exception as err:  # pylint: disable=broad-except
			if isinstance(_app, FastAPI) and not _app.is_shutting_down and not isinstance(err, ConnectionClosedOK):
				logger.error(err, exc_info=True)
			break


async def mq_websocket_reader(websocket: WebSocket):
	try:
		await websocket.receive_bytes()
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)


@messagebroker_router.get("/")
async def messagebroker_index():
	return HTMLResponse("<h1>messagebroker</h1>")


@messagebroker_router.websocket("")
async def mq_websocket_endpoint(websocket: WebSocket, params: dict = Depends(mq_websocket_parameters)):
	session = contextvar_client_session.get()
	if not session.user_store.host or not session.user_store.isAdmin:
		logger.warning("Access to mq websocket denied for user '%s'", session.user_store.username)
		await websocket.close(code=4403)
		return

	await websocket.accept()

	channel = f"host.{session.user_store.host.id}"
	last_id = params["last_id"]

	logger.info("Websocket client connected to mq stream: channel=%s, last_id=%s", channel, last_id)
	await asyncio.gather(mq_websocket_reader(websocket), mq_websocket_writer(websocket, channel=channel, last_id=last_id))
