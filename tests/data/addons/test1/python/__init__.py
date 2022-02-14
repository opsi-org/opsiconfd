# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
addon test1
"""

import os
import pathlib

from fastapi import FastAPI, APIRouter, status, HTTPException
from fastapi.requests import HTTPConnection
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import Receive, Send

from OPSI.Exceptions import BackendAuthenticationError, BackendPermissionDeniedError

from opsiconfd.addon import Addon
from opsiconfd.utils import remove_route_path
from opsiconfd.session import ACCESS_ROLE_PUBLIC, ACCESS_ROLE_AUTHENTICATED

from .const import ADDON_ID, ADDON_NAME, ADDON_VERSION
from .rest import api_router

router = APIRouter()


@router.get("")
def index():
	return PlainTextResponse("Hello from addon test1")


@router.get("/public")
def public():
	return PlainTextResponse("Public addon test1")


@router.get("/login")
def login():
	return PlainTextResponse("login")


@router.get("/logout")
def logout():
	return PlainTextResponse("logout")


class AddonTest1(Addon):
	id = ADDON_ID
	name = ADDON_NAME
	version = ADDON_VERSION
	api_router = api_router

	def on_load(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called after loading the addon"""
		marker_dir = pathlib.Path("/var/lib/opsi/opsiconfd_test_addon")
		marker_dir.mkdir(exist_ok=True)
		try:
			marker_dir.chmod(0o777)
		except PermissionError:
			pass
		marker = marker_dir / "test1_on_load"
		marker.touch()
		try:
			marker.chmod(0o666)
		except PermissionError:
			pass
		router.include_router(api_router, prefix="/api")
		app.include_router(router, prefix=self.router_prefix)
		app.mount(
			path=f"{self.router_prefix}/static", app=StaticFiles(directory=os.path.join(self.data_path, "static"), html=True), name="static"
		)

	def on_unload(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called before unloading the addon"""
		marker_dir = pathlib.Path("/var/lib/opsi/opsiconfd_test_addon")
		marker_dir.mkdir(exist_ok=True)
		try:
			marker_dir.chmod(0o777)
		except PermissionError:
			pass
		marker = marker_dir / "test1_on_unload"
		marker.touch()
		try:
			marker.chmod(0o666)
		except PermissionError:
			pass
		remove_route_path(app, self.router_prefix)

	async def handle_request(
		self, connection: HTTPConnection, receive: Receive, send: Send
	) -> bool:  # pylint: disable=no-self-use,unused-argument
		"""Called on every request where the path matches the addons router prefix.
		Return true to skip further request processing."""
		connection.scope["required_access_role"] = ACCESS_ROLE_AUTHENTICATED
		if connection.scope["path"].startswith((f"{self.router_prefix}/public", f"{self.router_prefix}/static")):
			connection.scope["required_access_role"] = ACCESS_ROLE_PUBLIC
		elif connection.scope["path"] == f"{self.router_prefix}/login":
			connection.scope["session"].user_store.username = "fakeuser"
			connection.scope["session"].user_store.authenticated = True
			connection.scope["session"].user_store.isAdmin = False
			await connection.scope["session"].store()
		elif connection.scope["path"] == f"{self.router_prefix}/logout":
			await connection.scope["session"].delete()
		return False

	async def handle_request_exception(
		self, err: Exception, connection: HTTPConnection, receive: Receive, send: Send
	) -> bool:  # pylint: disable=no-self-use,unused-argument
		"""Called on every request exception where the path matches the addons router prefix.
		Return true to skip further request processing."""

		if isinstance(err, (HTTPException, BackendAuthenticationError, BackendPermissionDeniedError)):
			response = PlainTextResponse(
				status_code=status.HTTP_401_UNAUTHORIZED, content="addon_test1_error", headers={"X-Addon": "test1"}
			)
			await response(connection.scope, receive, send)
			return True

		return False
