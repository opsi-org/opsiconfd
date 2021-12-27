# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.application.jsonrpcinterface
"""

import os

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

from ..config import config
from ..backend import get_backend_interface

jsonrpc_interface_router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(config.static_dir, "templates"))

def jsonrpc_interface_setup(app):
	app.include_router(jsonrpc_interface_router, prefix="/interface")

@jsonrpc_interface_router.get("/")
async def jsonrpc_interface_index(request: Request):
	context = {
		"request": request,
		"interface": get_backend_interface()
	}
	return templates.TemplateResponse("interface.html", context)
