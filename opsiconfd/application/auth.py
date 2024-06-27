# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
session
"""

import asyncio
import time
from typing import Literal

from fastapi import APIRouter, FastAPI, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from opsicommon.logging.constants import TRACE
from opsiconfd.application.admininterface import admin_interface_index
from opsiconfd.auth.saml import get_saml_settings, saml_auth_request_data
from opsiconfd.config import opsi_config
from opsiconfd.logging import get_logger
from opsiconfd.rest import RESTResponse, rest_api
from opsiconfd.session import (
	OPSISession,
	_post_failed_authenticate,
	authenticate,
	ensure_session,
	post_authenticate,
	post_user_authenticate,
	pre_authenticate,
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


@auth_router.get("/session_id")
@auth_router.post("/session_id")
@rest_api
async def session_id(request: Request) -> RESTResponse:
	await pre_authenticate(request.scope)
	session = request.scope.get("session")
	assert session
	await session.store()
	assert session and session.session_id
	return RESTResponse(session.session_id)


@auth_router.get("/authenticated")
@auth_router.post("/authenticated")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def authenticated(request: Request) -> RESTResponse:
	session: OPSISession | None = request.scope.get("session")
	if session:
		if session.authenticated:
			return RESTResponse(True)
		try:
			params = await request.json()
		except Exception:
			params = {}
		timeout_ts = time.time() + int(params.get("wait_time", 0))
		while time.time() < timeout_ts:
			await session.refresh()
			if session.authenticated:
				return RESTResponse(True)
			await asyncio.sleep(1)
	return RESTResponse(False, http_status=status.HTTP_401_UNAUTHORIZED)


async def _saml_login(request: Request, redirect_url: str) -> RedirectResponse:
	session: OPSISession = await ensure_session(request.scope)
	await session.store()
	assert session.session_id
	redirect_url += f"?session_id={session.session_id}"
	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings(login_callback_path=redirect_url))
	redirect_url = auth.login()
	return RedirectResponse(url=redirect_url)


@auth_router.get("/saml/login")
async def saml_login(request: Request) -> RedirectResponse:
	return await _saml_login(request=request, redirect_url="/auth/saml/callback/login")


@auth_router.get("/saml/login/configed")
async def saml_login_configed(request: Request) -> RedirectResponse:
	return await _saml_login(request=request, redirect_url="/auth/saml/callback/login/configed")


@auth_router.get("/saml/logout")
async def saml_logout(request: Request) -> RedirectResponse:
	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
	redirect_url = auth.logout()
	return RedirectResponse(url=redirect_url)


async def _saml_callback_login(request: Request, success_action: Literal["redirect_to_admin", "close"] = "redirect_to_admin") -> Response:
	# TODO: https://github.com/SAML-Toolkits/python3-saml#avoiding-replay-attacks
	await pre_authenticate(request.scope)
	session: OPSISession = request.scope["session"]

	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
	await run_in_threadpool(auth.process_response)
	if logger.isEnabledFor(TRACE):
		logger.trace(auth.get_last_response_xml())
	errors = auth.get_errors()
	response = PlainTextResponse("Authentication failure", status_code=status.HTTP_401_UNAUTHORIZED)
	if errors:
		logger.error("Failed to process SAML SSO response: %s %s", errors, auth.get_last_error_reason())
	elif auth.is_authenticated():
		roles = [
			g.lower()
			for g in auth.get_attribute("Role") or auth.get_attribute("http://schemas.microsoft.com/ws/2008/06/identity/claims/role") or []
		]
		logger.info("SAML SSO successful for user %s with roles %s", auth.get_nameid(), roles)
		is_admin = (opsi_config.get("groups", "admingroup") or "").lower() in roles
		if auth.get_nameid() and is_admin:
			session.username = auth.get_nameid()
			session.user_groups = set(roles)
			session.is_admin = is_admin
			session.authenticated = True

			await post_user_authenticate(request.scope)
			await post_authenticate(request.scope)
			if success_action == "close":
				return HTMLResponse(
					"<html><body><p>The login was successful, you can close this window.</p>"
					"<script>window.close();</script></body></html>",
					status_code=status.HTTP_200_OK,
				)
			return await admin_interface_index(request)

		logger.info("Not an admin user '%s'", auth.get_nameid())
		response = PlainTextResponse("Access denied", status_code=status.HTTP_403_FORBIDDEN)

	await _post_failed_authenticate(request.scope)
	return response


@auth_router.post("/saml/callback/login")
async def saml_callback_login(request: Request) -> Response:
	return await _saml_callback_login(request=request)


@auth_router.post("/saml/callback/login/configed")
async def saml_callback_login_configed(request: Request) -> Response:
	return await _saml_callback_login(request=request, success_action="close")


@auth_router.post("/saml/callback/logout")
async def saml_callback_logout(request: Request) -> RedirectResponse:
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
