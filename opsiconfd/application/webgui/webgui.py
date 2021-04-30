# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from opsiconfd.logging import logger
from opsiconfd.backend import get_backend

webgui_router = APIRouter()

def webgui_setup(app):
	app.include_router(webgui_router, prefix="/webgui")

@webgui_router.options("/api/{any:path}")
async def options():
	return Response(
		status_code=200
	)

@webgui_router.get("/api/opsidata/clients")
@webgui_router.post("/api/opsidata/clients")
async def api(request: Request):  # pylint: disable=too-many-branches
	#request_data = await request.json()
	#logger.devel(request_data)
	response = JSONResponse({"error": "none"})
	return response
