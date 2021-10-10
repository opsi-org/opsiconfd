# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
addon test1
"""

import os
import tempfile

from fastapi import FastAPI, APIRouter
from fastapi.routing import APIRoute
from fastapi.responses import PlainTextResponse

from opsiconfd.addon import Addon
from opsiconfd.logging import logger
from opsiconfd.utils import remove_router

from .const import ADDON_ID, ADDON_NAME, ADDON_VERSION

router = APIRouter()

@router.get("")
def index():
	return PlainTextResponse("Hello from addon test1")

class AddonTest1(Addon):
	id = ADDON_ID
	name = ADDON_NAME
	version = ADDON_VERSION

	def on_load(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called after loading the addon"""
		with open(os.path.join(tempfile.gettempdir(), "opsiconfd_test_addon_test1_on_load"), mode="w", encoding="utf8"):
			pass
		app.include_router(router, prefix=self.router_prefix)

	def on_unload(self, app: FastAPI) -> None:  # pylint: disable=no-self-use
		"""Called before unloading the addon"""
		with open(os.path.join(tempfile.gettempdir(), "opsiconfd_test_addon_test1_on_unload"), mode="w", encoding="utf8"):
			pass
		remove_router(app, router, self.router_prefix)
