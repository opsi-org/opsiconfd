# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
addon test1
"""
import os
from typing import Optional
import tempfile

from fastapi import FastAPI, APIRouter
from fastapi.routing import APIRoute
from fastapi.responses import PlainTextResponse

from opsiconfd.addon import Addon
from opsiconfd.logging import logger
from opsiconfd.utils import remove_router

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from opsiconfd import contextvar_client_session
from opsiconfd.backend import get_backend
from opsiconfd.config import config
from opsiconfd.logging import logger

from .webgui import webgui_setup, webgui_router
from .hosts import host_router
from .clients import client_router
from .products import product_router
from .depots import depot_router
from .utils import get_mysql, get_allowed_objects, build_tree, get_username, get_configserver_id

WEBGUI_APP_PATH = config.webgui_folder
webgui_router = APIRouter()

mysql = get_mysql()

class Webgui(Addon):
	id = "webgui"
	name = "webgui"
	version = "1.0"

	def on_load(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called after loading the addon"""
		logger.devel("on_load")
		webgui_setup(app)

	def on_unload(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called before unloading the addon"""

		remove_router(app, webgui_router,"/webgui")
		remove_router(app, host_router,"/webgui")
		remove_router(app, client_router,"/webgui")
		remove_router(app, product_router,"/webgui")
		remove_router(app, depot_router,"/webgui")

		#TODO unmount webui
