# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
session
"""

from fastapi import APIRouter, FastAPI, Request, status
from pydantic import BaseModel  # pylint: disable=no-name-in-module

from opsiconfd.rest import RESTResponse, rest_api
from opsiconfd.session import authenticate, get_session

session_router = APIRouter()


def session_setup(app: FastAPI) -> None:
	app.include_router(router=session_router, prefix="/session")


class LoginData(BaseModel):
	username: str
	password: str


@session_router.post("/login")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def login(request: Request, login_data: LoginData) -> RESTResponse:
	await authenticate(request.scope, username=login_data.username, password=login_data.password)
	return RESTResponse({"session_id": request.scope["session"].session_id})


@session_router.get("/logout")
@session_router.post("/logout")
@rest_api
async def logout(request: Request) -> RESTResponse:
	if request.scope["session"]:
		await request.scope["session"].delete()
	return RESTResponse("session deleted")


@session_router.get("/authenticated")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def authenticated(request: Request) -> RESTResponse:
	if request.scope["session"] and request.scope["session"].user_store.authenticated:
		return RESTResponse(True)
	return RESTResponse(False, http_status=status.HTTP_401_UNAUTHORIZED)
