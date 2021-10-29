# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
addon webgui
"""

import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from opsiconfd.addon import Addon
from opsiconfd.logging import logger
from opsiconfd.config import config
from opsiconfd.utils import remove_router
from opsiconfd.backend import get_mysql

from .const import ADDON_ID, ADDON_NAME, ADDON_VERSION
from .clients import client_router
from .products import product_router
from .depots import depot_router
from .hosts import host_router
from .webgui import webgui_router

WEBGUI_APP_PATH = config.webgui_folder


class Webgui(Addon):
	id = ADDON_ID
	name = ADDON_NAME
	version = ADDON_VERSION


	def setup(self, app):

		try:
			get_mysql()
		except RuntimeError as err:
			logger.warning("No mysql backend! Webgui only works with mysql backend.")
			raise RuntimeError("No mysql backend! Webgui only works with mysql backend.") from err

		app.include_router(webgui_router, prefix=self.router_prefix)
		app.include_router(product_router, prefix=self.router_prefix)
		app.include_router(host_router, prefix=self.router_prefix)
		app.include_router(client_router, prefix=self.router_prefix)
		app.include_router(depot_router, prefix=self.router_prefix)

		if os.path.isdir(WEBGUI_APP_PATH):
			app.mount(f"{ADDON_ID}/app", StaticFiles(directory=WEBGUI_APP_PATH, html=True), name="app")

	def on_load(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called after loading the addon"""
		logger.devel("on_load")
		self.setup(app)

	def on_unload(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called before unloading the addon"""

		remove_router(app, webgui_router, self.router_prefix)
		remove_router(app, host_router, self.router_prefix)
		remove_router(app, client_router, self.router_prefix)
		remove_router(app, product_router, self.router_prefix)
		remove_router(app, depot_router, self.router_prefix)

		#TODO unmount webui
