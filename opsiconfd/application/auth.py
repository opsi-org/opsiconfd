# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
session
"""

import asyncio
import json
import time
from base64 import b64decode
from datetime import UTC, datetime

from fastapi import APIRouter, FastAPI, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from opsi.logging import TRACE
from opsi.opsi.service.model.object import AuditLogAuthenticationLogoutReason, AuditLogEventType
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from opsiconfd.auth.const import AuthenticationMethod
from opsiconfd.auth.saml import (
	SAML_STATUS_SUCCESS,
	build_login_redirect_url,
	build_logout_redirect_url,
	generate_saml_id,
	get_logout_response_status,
	get_sp_metadata_xml,
	validate_login_response,
)
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import get_logger
from opsiconfd.redis import async_redis_client
from opsiconfd.rest import RESTResponse, rest_api
from opsiconfd.session import (
	OPSISession,
	_post_failed_authenticate,
	audit_authentication_event,
	authenticate,
	ensure_session,
	post_authenticate,
	post_user_authenticate,
	pre_authenticate,
)
from opsiconfd.utils import asyncio_create_task

logger = get_logger()
saml_logger = get_logger("opsiconfd.saml")
auth_router = APIRouter()

# Lifetime in seconds of a pending SAML login request ID in Redis (time allowed to complete the login at the IdP)
SAML_LOGIN_REQUEST_LIFETIME = 600


def auth_setup(app: FastAPI) -> None:
	app.include_router(router=auth_router, prefix="/auth")


class LoginData(BaseModel):
	username: str
	password: str
	mfa_otp: str | None = None


@auth_router.post("/login")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def login(request: Request, login_data: LoginData) -> RESTResponse:
	await authenticate(scope=request.scope, username=login_data.username, password=login_data.password, mfa_otp=login_data.mfa_otp)
	session: OPSISession = request.scope["session"]
	return RESTResponse({"session_id": session.session_id, "is_admin": session.is_admin})


@auth_router.get("/logout")
@auth_router.post("/logout")
@rest_api
async def logout(request: Request) -> RESTResponse:
	session: OPSISession | None = request.scope.get("session")
	if session:
		await session.delete()
		asyncio_create_task(
			audit_authentication_event(
				scope=request.scope,
				event_type=AuditLogEventType.AUTHENTICATION_LOGOUT,
				logout_reason=AuditLogAuthenticationLogoutReason.USER_REQUESTED,
			)
		)
	return RESTResponse("session deleted")


@auth_router.get("/session_id")
@auth_router.post("/session_id")
@rest_api
async def session_id(request: Request) -> RESTResponse:
	await pre_authenticate(request.scope)
	session: OPSISession | None = request.scope.get("session")
	assert session and session.session_id
	await session.store(wait=True)
	return RESTResponse(session.session_id)


@auth_router.get("/authenticated")
@auth_router.post("/authenticated")
@rest_api(default_error_status_code=status.HTTP_401_UNAUTHORIZED)
async def authenticated(request: Request) -> RESTResponse:
	session: OPSISession | None = request.scope.get("session")
	if session and session.authenticated:
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


@auth_router.get("/saml/sp-meta.xml")
async def saml_sp_meta_xml() -> Response:
	return Response(content=get_sp_metadata_xml(), media_type="application/xml")


@auth_router.get("/saml/login")
async def saml_login(request: Request) -> RedirectResponse:
	session_id = request.query_params.get("session_id")
	logger.debug(f"SAML login requested {'with' if session_id else 'without'} session_id")
	session: OPSISession = await ensure_session(request.scope, session_id=session_id)
	session.authenticated = False
	await session.store()
	relay_state_data = {
		"session_id": session.session_id,
		"redirect": request.query_params.get("redirect", "/admin"),
	}
	if saml_logger.isEnabledFor(TRACE):
		saml_logger.trace("SAML Login RelayState data: %s", relay_state_data)

	# Store the SAML request ID in Redis to verify InResponseTo of the SAML response.
	# This prevents replay attacks and unsolicited (IdP initiated) SAML responses.
	request_id = generate_saml_id()
	redis = await async_redis_client()
	redis_key = f"{config.redis_key('saml_login_request_ids')}:{request_id}"
	await redis.set(redis_key, session.session_id or "", ex=SAML_LOGIN_REQUEST_LIFETIME)

	redirect_url = await run_in_threadpool(build_login_redirect_url, request_id, json.dumps(relay_state_data))
	return RedirectResponse(url=redirect_url)


@auth_router.get("/saml/logout")
async def saml_logout(request: Request) -> RedirectResponse:
	session: OPSISession | None = request.scope.get("session")
	redirect_url = "/"
	if session:
		username = session.username
		await session.delete()
		asyncio_create_task(
			audit_authentication_event(
				scope=request.scope,
				event_type=AuditLogEventType.AUTHENTICATION_LOGOUT,
				logout_reason=AuditLogAuthenticationLogoutReason.USER_REQUESTED,
			)
		)
		if config.saml_idp_slo_url:
			redirect_url = await run_in_threadpool(build_logout_redirect_url, username)
			if saml_logger.isEnabledFor(TRACE):
				saml_logger.trace("SAML Logout redirect URL: %s", redirect_url)

	return RedirectResponse(url=redirect_url)


@auth_router.get("/saml/callback/login")
@auth_router.post("/saml/callback/login")
async def saml_callback_login(request: Request) -> Response:
	try:
		form_data = await request.form()
		saml_response = form_data.get("SAMLResponse")
		if not saml_response or not isinstance(saml_response, str):
			raise RuntimeError("No SAMLResponse in SAML login callback")
		if saml_logger.isEnabledFor(TRACE):
			saml_logger.trace("SAML Login Callback SAMLResponse: %s", b64decode(saml_response))

		relay_state = form_data.get("RelayState")
		if not relay_state or not isinstance(relay_state, str):
			raise RuntimeError("No RelayState in SAML login callback")

		try:
			relay_state_data = json.loads(relay_state)
			session_id = relay_state_data["session_id"]
		except Exception as err:
			raise RuntimeError(f"Failed to parse RelayState in SAML login callback: {err}") from err

		if saml_logger.isEnabledFor(TRACE):
			saml_logger.trace("SAML Login Callback RelayState data: %s", relay_state_data)

		redirect = relay_state_data.get("redirect") or "/admin"

		await pre_authenticate(request.scope, session_id=session_id)
		session: OPSISession = request.scope["session"]

		response = await run_in_threadpool(validate_login_response, saml_response)

		# Verify that the SAML response answers a login request initiated by this SP.
		# Each request ID can only be consumed once, which also prevents replay attacks.
		if not response.in_response_to:
			raise RuntimeError("SAML SSO response has no InResponseTo")
		redis = await async_redis_client()
		redis_key = f"{config.redis_key('saml_login_request_ids')}:{response.in_response_to}"
		stored_session_id = await redis.getdel(redis_key)
		if not stored_session_id:
			raise RuntimeError(f"SAML SSO response unsolicited or already processed: {response.in_response_to!r}")
		if stored_session_id.decode("utf-8") != session_id:
			raise RuntimeError("Session ID mismatch in SAML login callback")

		# Entra ID does not support SessionNotOnOrAfter attribute
		expiration_seconds = 3600
		if response.session_not_on_or_after is not None:
			expiration_seconds = int((response.session_not_on_or_after - datetime.now(tz=UTC)).total_seconds())
			if expiration_seconds <= 0:
				raise RuntimeError(f"SAML SSO response session expired at {response.session_not_on_or_after}")

		username = response.name_id
		if not username:
			raise RuntimeError("SAML SSO response has no NameID")

		def get_attribute_values(name: str) -> list[str]:
			"""Return all values of the SAML attributes with the given name."""
			values: list[str] = []
			for attribute in response.attributes:
				if attribute.name == name:
					values.extend(v for v in attribute.values if v)
			return values

		roles = [
			r.lower()
			for r in (
				get_attribute_values("Role")
				or get_attribute_values("http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
				or get_attribute_values("groupMembership")
			)
		]
		saml_logger.info("SAML SSO successful for user %s with roles %s", username, roles)

		mappings = {}
		for mapping in config.saml_role_group_mappings:
			tmp = mapping.rsplit("=", 1)
			if len(tmp) == 1:
				saml_logger.error("Failed to parse saml role group mapping: %r", mapping)
				continue
			mappings[tmp[0].strip().lower()] = tmp[1].strip().lower()
		saml_logger.debug("SAML role group mappings %s", mappings)
		groups = {mappings.get(role, role) for role in roles}
		saml_logger.info("SAML roles mapped to groups %s", groups)

		is_admin = (opsi_config.get("groups", "admingroup") or "").lower() in groups
		if not is_admin:
			raise RuntimeError(f"Not an admin user {username!r}")

		session.username = username
		session.user_groups = groups
		session.is_admin = is_admin
		session.authenticated = True
		session.auth_methods = {AuthenticationMethod.SAML}

		await post_user_authenticate(request.scope)
		await post_authenticate(request.scope)
		if redirect == "close_window":
			return HTMLResponse(
				"<html><body><p>The login was successful, you can close this window.</p><script>window.close();</script></body></html>",
			)
		return HTMLResponse(
			f'<html><head><meta http-equiv="refresh" content="0; url={redirect}"><head></html>',
		)

	except Exception as err:
		saml_logger.error("SAML login error: %s", err, exc_info=True)
		await _post_failed_authenticate(request.scope)
		return PlainTextResponse("Authentication failure", status_code=status.HTTP_401_UNAUTHORIZED)


@auth_router.get("/saml/callback/logout")
@auth_router.post("/saml/callback/logout")
async def saml_callback_logout(request: Request) -> RedirectResponse:
	try:
		form_data = await request.form()
		saml_response = request.query_params.get("SAMLResponse") or form_data.get("SAMLResponse")
		if not saml_response or not isinstance(saml_response, str):
			raise RuntimeError("No SAMLResponse in SAML logout callback")
		status_value = await run_in_threadpool(get_logout_response_status, saml_response)
		if saml_logger.isEnabledFor(TRACE):
			saml_logger.trace("SAML Logout Callback status: %s", status_value)
		if status_value == SAML_STATUS_SUCCESS:
			saml_logger.info("SAML SLO successful")
		else:
			saml_logger.error("Failed to process SAML SLO response, status: %s", status_value)
	except Exception as err:
		saml_logger.error("SAML logout error: %s", err, exc_info=True)

	session: OPSISession | None = request.scope.get("session")
	if session:
		await session.delete()
		asyncio_create_task(
			audit_authentication_event(
				scope=request.scope,
				event_type=AuditLogEventType.AUTHENTICATION_LOGOUT,
				logout_reason=AuditLogAuthenticationLogoutReason.USER_REQUESTED,
			)
		)

	return RedirectResponse("/")
