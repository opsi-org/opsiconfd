# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
addon webgui
"""

import os

from fastapi import FastAPI, Request, status, HTTPException, APIRouter
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.requests import HTTPConnection
from starlette.types import Receive, Send
from starlette.concurrency import run_in_threadpool

from opsiconfd.addon import Addon
from opsiconfd.logging import logger
from opsiconfd.config import config
from opsiconfd.utils import remove_route_path
from opsiconfd.backend import get_client_backend

from opsiconfd.session import ACCESS_ROLE_AUTHENTICATED, ACCESS_ROLE_PUBLIC

from .const import ADDON_ID, ADDON_NAME, ADDON_VERSION
from .clients import client_router
from .products import product_router
from .depots import depot_router
from .hosts import host_router
from .webgui import webgui_router
from .utils import mysql

WEBGUI_APP_PATH = config.webgui_folder
SESSION_LIFETIME = 60*30



class Webgui(Addon):
	id = ADDON_ID
	name = ADDON_NAME
	version = ADDON_VERSION


	def setup(self, app):

		if not mysql:
			logger.warning("No mysql backend found! Webgui only works with mysql backend.")
			error_router = APIRouter()
			@error_router.get(f"/{ADDON_ID}/app")
			def webgui_error():
				return PlainTextResponse("No mysql backend found! Webgui only works with mysql backend.", status_code=501)
			app.include_router(error_router)
			logger.devel(app)

			return

		app.include_router(webgui_router, prefix=self.router_prefix)
		app.include_router(product_router, prefix=self.router_prefix)
		app.include_router(host_router, prefix=self.router_prefix)
		app.include_router(client_router, prefix=self.router_prefix)
		app.include_router(depot_router, prefix=self.router_prefix)

		if os.path.isdir(WEBGUI_APP_PATH):
			app.mount(f"/{ADDON_ID}/app", StaticFiles(directory=WEBGUI_APP_PATH, html=True), name="app")

	def on_load(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called after loading the addon"""
		self.setup(app)

	def on_unload(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called before unloading the addon"""
		remove_route_path(app, self.router_prefix)


	async def handle_request(self, connection: HTTPConnection, receive: Receive, send: Send) -> bool:  # pylint: disable=no-self-use,unused-argument
		"""Called on every request where the path matches the addons router prefix.
		Return true to skip further request processing."""
		connection.scope["required_access_role"] = ACCESS_ROLE_AUTHENTICATED

		if (
			connection.scope["path"].startswith(f"{self.router_prefix}/api/opsidata") and
			connection.base_url.hostname in  ("127.0.0.1", "::1", "0.0.0.0", "localhost")
		):
			if connection.scope.get("method") == "OPTIONS":
				connection.scope["required_access_role"] = ACCESS_ROLE_PUBLIC
		if (connection.scope["path"].rstrip("/") == self.router_prefix
			or connection.scope["path"].startswith((f"{self.router_prefix}/app",f"{self.router_prefix}/api/user/opsiserver"))
		):
			connection.scope["required_access_role"] = ACCESS_ROLE_PUBLIC
		elif connection.scope["path"] == f"{self.router_prefix}/api/auth/login":
			if connection.scope.get("method") == "OPTIONS":
				connection.scope["required_access_role"] = ACCESS_ROLE_PUBLIC
			else:
				try:
					await authenticate(connection, receive)
					connection.scope["session"].max_age = SESSION_LIFETIME
				except Exception as err:
					raise HTTPException(
						status_code=status.HTTP_403_FORBIDDEN,
						detail=str(err)
					) from err

		return False

async def authenticate(connection: HTTPConnection, receive: Receive) -> None:
	logger.info("Start authentication of client %s", connection.client.host)
	username = None
	password = None
	if connection.scope["path"] == "/addons/webgui/api/auth/login":
		req = Request(connection.scope, receive)
		form = await req.form()
		username = form.get("username")
		password = form.get("password")

	auth_type = None
	def sync_auth(username, password, auth_type):
		get_client_backend().backendAccessControl.authenticate(username, password, auth_type=auth_type)

	await run_in_threadpool(sync_auth, username, password, auth_type)
