# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
session
"""

import asyncio
import json
import time
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]
from opsicommon.logging.constants import TRACE
from opsicommon.utils import unix_timestamp
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from opsiconfd.auth import AuthenticationMethod
from opsiconfd.auth.saml import get_saml_settings, saml_auth_request_data
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import get_logger
from opsiconfd.redis import async_redis_client
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
	return RESTResponse(False, http_status=status.HTTP_401_UNAUTHORIZED)


@auth_router.get("/wait_authenticated")
@auth_router.post("/wait_authenticated")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def wait_authenticated(request: Request) -> RESTResponse:
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


@auth_router.get("/saml/login")
async def saml_login(request: Request) -> RedirectResponse:
	session_id = request.query_params.get("session_id")
	session: OPSISession = await ensure_session(request.scope, session_id=session_id)
	await session.store()
	relay_state_data = {
		"session_id": session.session_id,
		"redirect": request.query_params.get("redirect", "/admin"),
	}
	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
	# The value passed as return_to will be send as RelayState in the SAML request
	redirect_url = auth.login(return_to=json.dumps(relay_state_data))
	return RedirectResponse(url=redirect_url)


@auth_router.get("/saml/logout")
async def saml_logout(request: Request) -> RedirectResponse:
	request_data = await saml_auth_request_data(request)
	auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
	redirect_url = auth.logout()
	return RedirectResponse(url=redirect_url)


@auth_router.post("/saml/callback/login")
async def saml_callback_login(request: Request) -> Response:
	try:
		request_data = await saml_auth_request_data(request)
		relay_state = request_data.get("post_data", {}).get("RelayState")
		if not relay_state:
			raise RuntimeError("No RelayState in SAML login callback")

		try:
			relay_state_data = json.loads(relay_state)
			session_id = relay_state_data["session_id"]
		except Exception as err:
			raise RuntimeError(f"Failed to parse RelayState in SAML login callback: {err}") from err

		redirect = relay_state_data.get("redirect") or "/admin"

		await pre_authenticate(request.scope, session_id=session_id)
		session: OPSISession = request.scope["session"]

		auth = OneLogin_Saml2_Auth(request_data, get_saml_settings())
		await run_in_threadpool(auth.process_response)
		if logger.isEnabledFor(TRACE):
			logger.trace(auth.get_last_response_xml())

		errors = auth.get_errors()
		if errors:
			raise RuntimeError(f"Failed to process SAML SSO response: {errors} {auth.get_last_error_reason()}")

		expiration_ts = auth.get_session_expiration()
		expiration_time = datetime.fromtimestamp(expiration_ts, tz=timezone.utc)
		expiration_seconds = expiration_ts - unix_timestamp()
		if expiration_seconds <= 0:
			raise RuntimeError(f"SAML SSO response session expired at {expiration_time}")

		if not auth.is_authenticated():
			raise RuntimeError("SAML SSO not authenticated")

		# https://github.com/SAML-Toolkits/python3-saml#avoiding-replay-attacks
		last_assertion_id = auth.get_last_assertion_id()
		assert last_assertion_id
		redis_key = f"{config.redis_key('saml_processed_assertion_ids')}:{last_assertion_id}"
		redis = await async_redis_client()
		if await redis.exists(redis_key):
			raise RuntimeError(f"SAML SSO response already processed: {last_assertion_id!r}")
		await redis.set(redis_key, "1", ex=int(expiration_seconds) + 60)

		username = auth.get_nameid()
		if not username:
			raise RuntimeError("SAML SSO response has no NameID")

		roles = [
			g.lower()
			for g in auth.get_attribute("Role") or auth.get_attribute("http://schemas.microsoft.com/ws/2008/06/identity/claims/role") or []
		]

		logger.info("SAML SSO successful for user %s with roles %s", username, roles)
		is_admin = (opsi_config.get("groups", "admingroup") or "").lower() in roles

		if not is_admin:
			raise RuntimeError(f"Not an admin user {username!r}")

		session.username = username
		session.user_groups = set(roles)
		session.is_admin = is_admin
		session.authenticated = True
		session.auth_methods = {AuthenticationMethod.SAML}

		await post_user_authenticate(request.scope)
		await post_authenticate(request.scope)
		if redirect == "close_window":
			return HTMLResponse(
				"<html><body><p>The login was successful, you can close this window.</p>" "<script>window.close();</script></body></html>",
			)
		return HTMLResponse(
			f'<html><head><meta http-equiv="refresh" content="0; url={redirect}"><head></html>',
		)

	except Exception as err:
		logger.error("SAML login error: %s", err)
		await _post_failed_authenticate(request.scope)
		return PlainTextResponse("Authentication failure", status_code=status.HTTP_401_UNAUTHORIZED)


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
