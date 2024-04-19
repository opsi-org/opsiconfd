# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
session
"""

from fastapi import APIRouter, FastAPI, Request, Response, status
from fastapi.responses import PlainTextResponse, RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from opsiconfd.application.admininterface import admin_interface_index
from opsiconfd.auth.saml import get_saml_settings, saml_auth_request_data
from opsiconfd.config import opsi_config
from opsiconfd.logging import get_logger
from opsiconfd.rest import RESTResponse, rest_api
from opsiconfd.session import (
	OPSISession,
	_post_authenticate,
	_post_failed_authenticate,
	_post_user_authenticate,
	_pre_authenticate,
	authenticate,
)

logger = get_logger()
auth_router = APIRouter()


def auth_setup(app: FastAPI) -> None:
	app.include_router(router=auth_router, prefix="/auth")


class LoginData(BaseModel):
	username: str
	password: str
	mfa_otp: str | None = None


@auth_router.post("/login")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def login(request: Request, login_data: LoginData) -> RESTResponse:
	await authenticate(request.scope, username=login_data.username, password=login_data.password, mfa_otp=login_data.mfa_otp)
	session: OPSISession = request.scope["session"]
	return RESTResponse({"session_id": session.session_id, "is_admin": session.is_admin})


@auth_router.get("/logout")
@auth_router.post("/logout")
@rest_api
async def logout(request: Request) -> RESTResponse:
	session: OPSISession | None = request.scope.get("session")
	if session:
		await session.delete()
	return RESTResponse("session deleted")


@auth_router.get("/authenticated")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def authenticated(request: Request) -> RESTResponse:
	if request.scope["session"] and request.scope["session"].authenticated:
		return RESTResponse(True)
	return RESTResponse(False, http_status=status.HTTP_401_UNAUTHORIZED)


@auth_router.get("/saml/login")
async def saml_login(request: Request) -> RedirectResponse:
	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
	redirect_url = auth.login()
	return RedirectResponse(url=redirect_url)


@auth_router.get("/saml/logout")
async def saml_logout(request: Request) -> RedirectResponse:
	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
	redirect_url = auth.logout()
	return RedirectResponse(url=redirect_url)


@auth_router.post("/saml/login_callback")
async def saml_login_callback(request: Request) -> Response:
	# TODO: https://github.com/SAML-Toolkits/python3-saml#avoiding-replay-attacks
	await _pre_authenticate(request.scope)
	session: OPSISession = request.scope["session"]

	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
	await run_in_threadpool(auth.process_response)
	errors = auth.get_errors()
	response = PlainTextResponse("Authentication failure", status_code=status.HTTP_401_UNAUTHORIZED)
	if errors:
		logger.error("Failed to process SAML SSO response: %s %s", errors, auth.get_last_error_reason())
	elif auth.is_authenticated():
		roles = [g.lower() for g in auth.get_attribute("Role") or []]
		logger.info("SAML SSO successful for user %s with roles %s", auth.get_nameid(), roles)
		is_admin = (opsi_config.get("groups", "admingroup") or "").lower() in roles
		if auth.get_nameid() and is_admin:
			session.username = auth.get_nameid()
			session.user_groups = set(roles)
			session.is_admin = is_admin
			session.authenticated = True

			await _post_user_authenticate(request.scope)
			await _post_authenticate(request.scope)
			return await admin_interface_index(request)

		logger.info("Not an admin user '%s'", auth.get_nameid())
		response = PlainTextResponse("Access denied", status_code=status.HTTP_403_FORBIDDEN)

	await _post_failed_authenticate(request.scope)
	return response


@auth_router.post("/saml/logout_callback")
async def saml_logout_callback(request: Request) -> RedirectResponse:
	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
	await run_in_threadpool(auth.process_slo)
	errors = auth.get_errors()
	if errors:
		logger.error("Failed to process SAML SLO response: %s %s", errors, auth.get_last_error_reason())
	else:
		logger.info("SAML SLO successful")

	session: OPSISession | None = request.scope.get("session")
	if session:
		await session.delete()
	return RedirectResponse("/")
