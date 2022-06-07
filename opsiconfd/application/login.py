# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
login
"""

from fastapi import APIRouter, Request, status
from pydantic import BaseModel  # pylint: disable=no-name-in-module

from opsiconfd.config import config
from opsiconfd.rest import rest_api
from opsiconfd.session import authenticate, get_session

login_router = APIRouter()
logout_router = APIRouter()


def login_setup(app):
	app.include_router(router=login_router, prefix="/login")
	app.include_router(router=logout_router, prefix="/logout")


@login_router.get("")
@login_router.get("/")
async def login_index(request: Request):
	context = {
		"request": request,
	}
	return config.jinja_templates.TemplateResponse("login.html", context)


class LoginData(BaseModel):
	username: str
	password: str


@login_router.post("")
@login_router.post("/")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def login(request: Request, login_data: LoginData):
	if not request.scope["session"]:
		request.scope["session"] = await get_session(client_addr=request.scope["client"][0], headers=request.headers)

	await authenticate(request.scope["session"], username=login_data.username, password=login_data.password)
	return {"data": {"session_id": request.scope["session"].session_id}}


@logout_router.get("")
@logout_router.get("/")
@rest_api
async def logout(request: Request):
	if request.scope["session"]:
		await request.scope["session"].delete()
	return {"data": "session deleted"}
