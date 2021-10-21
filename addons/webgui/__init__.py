# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
addon webgui
"""

from fastapi import FastAPI

from opsiconfd.addon import Addon
from opsiconfd.logging import logger
from opsiconfd.utils import remove_router

from .webgui import webgui_setup, webgui_router
from .hosts import host_router
from .clients import client_router
from .products import product_router
from .depots import depot_router

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
