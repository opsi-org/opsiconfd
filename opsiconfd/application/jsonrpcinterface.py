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
:license: GNU Affero General Public License version 3
"""

from fastapi.responses import HTMLResponse
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

import os
import json


from ..logging import logger
from ..config import config

from ..backend import get_client_backend, get_backend_interface

jsonrpc_interface_router = APIRouter()


templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

def jsonrpc_interface_setup(app):
	app.include_router(jsonrpc_interface_router, prefix="/interface")

@jsonrpc_interface_router.get("/?")
async def jsonrpc_interface_index(request: Request):
	interface = get_backend_interface()
	methods = []
	for method in interface:
	# 	logger.notice(method.get("name"))
		methods.append(method.get("name"))
	# logger.notice(methods)


	template = "interface.html"
	# context = {"methods": methods}
	interfaceJSON = json.dumps(interface)
	context = {
		"request": request,
		"interface": interface,
		"methods": methods,
		"interfaceJSON": interfaceJSON,
		"testVar": "hallo"
		}
	
	# return HTMLResponse('<html><body><h1>Hello, world!</h1></body></html>',)
	return templates.TemplateResponse(template, context)

@jsonrpc_interface_router.post("/jsonrpc")
async def test(request: Request):
	# assert scope['type'] == 'http'
	# request = Request(scope, receive)
	test = await request.json()
	logger.notice(test)
	# logger.notice(body)
	logger.notice("test")
	return test
