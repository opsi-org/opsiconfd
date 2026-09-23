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
from opsi.time import unix_timestamp
from pydantic import BaseModel
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.saml import NAMEID_FORMAT_ENTITY, NameID
from saml2.sigver import RSACrypto, verify_redirect_signature
from saml2.xmldsig import SIG_RSA_SHA1
from starlette.concurrency import run_in_threadpool

from opsiconfd.auth.const import AuthenticationMethod
from opsiconfd.auth.saml import get_sp_metadata_xml, get_sp_url, saml_client
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

	with saml_client() as client:
		# The relay_state will be send as RelayState in the SAML request
		request_id, http_info = await run_in_threadpool(
			client.prepare_for_authenticate,
			relay_state=json.dumps(relay_state_data),
			binding=BINDING_HTTP_REDIRECT,
			response_binding=BINDING_HTTP_POST,
			sign=config.saml_sp_client_signature,
		)
	if saml_logger.isEnabledFor(TRACE):
		saml_logger.trace("SAML Login Request ID: %s, HTTP info: %s", request_id, http_info)
	return RedirectResponse(url=dict(http_info["headers"])["Location"])


@auth_router.get("/saml/logout")
async def saml_logout(request: Request) -> RedirectResponse:
	session: OPSISession | None = request.scope.get("session")
	redirect_url = "/"
	if session:
		await session.delete()
		asyncio_create_task(
			audit_authentication_event(
				scope=request.scope,
				event_type=AuditLogEventType.AUTHENTICATION_LOGOUT,
				logout_reason=AuditLogAuthenticationLogoutReason.USER_REQUESTED,
			)
		)

		if not config.saml_idp_slo_url:
			raise RuntimeError("The IdP does not support Single Log Out")

		with saml_client() as client:
			# Like python3-saml: The IdP entity ID is used as NameID
			request_id, logout_request = client.create_logout_request(
				destination=config.saml_idp_slo_url,
				issuer_entity_id=config.saml_idp_entity_id,
				name_id=NameID(text=config.saml_idp_entity_id, format=NAMEID_FORMAT_ENTITY),
				sign=False,
			)
			http_info = client.apply_binding(
				BINDING_HTTP_REDIRECT,
				str(logout_request),
				destination=config.saml_idp_slo_url,
				relay_state=get_sp_url(request.url.path),
				sign=config.saml_sp_client_signature,
			)
		if saml_logger.isEnabledFor(TRACE):
			saml_logger.trace("SAML Logout Request ID: %s, XML: %s", request_id, logout_request)
		redirect_url = dict(http_info["headers"])["Location"]

	return RedirectResponse(url=redirect_url)


@auth_router.get("/saml/callback/login")
@auth_router.post("/saml/callback/login")
async def saml_callback_login(request: Request) -> Response:
	try:
		form_data = await request.form()
		saml_response = form_data.get("SAMLResponse")
		if saml_logger.isEnabledFor(TRACE):
			saml_logger.trace("SAML Login Callback form data: %s", dict(form_data))
			saml_logger.trace(
				"SAML Login Callback Request SAMLResponse: %s", b64decode(saml_response if isinstance(saml_response, str) else "")
			)

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

		if not saml_response or not isinstance(saml_response, str):
			raise RuntimeError("No SAMLResponse in SAML login callback")

		with saml_client() as client:
			try:
				authn_response = await run_in_threadpool(client.parse_authn_request_response, saml_response, BINDING_HTTP_POST)
			except Exception as err:
				raise RuntimeError(f"Failed to process SAML SSO response: {err}") from err

		if saml_logger.isEnabledFor(TRACE) and authn_response:
			saml_logger.trace("SAML Login Callback Response XML: %s", authn_response)

		# PySAML2 returns a response without assertion if the response could not be verified
		if not authn_response or not authn_response.assertion:
			raise RuntimeError("SAML SSO not authenticated")

		# Entra ID does not support SessionNotOnOrAfter attribute
		expiration_seconds = 3600
		# 0 if SessionNotOnOrAfter is not set
		expiration_ts = authn_response.session_not_on_or_after
		if expiration_ts:
			expiration_time = datetime.fromtimestamp(expiration_ts, tz=UTC)
			expiration_seconds = expiration_ts - unix_timestamp()
			if expiration_seconds <= 0:
				raise RuntimeError(f"SAML SSO response session expired at {expiration_time}")

		# Avoiding replay attacks
		last_assertion_id = authn_response.assertion.id
		assert last_assertion_id
		redis_key = f"{config.redis_key('saml_processed_assertion_ids')}:{last_assertion_id}"
		redis = await async_redis_client()
		if await redis.exists(redis_key):
			raise RuntimeError(f"SAML SSO response already processed: {last_assertion_id!r}")
		await redis.set(redis_key, "1", ex=int(expiration_seconds) + 60)

		username = authn_response.name_id.text if authn_response.name_id else None
		if not username:
			raise RuntimeError("SAML SSO response has no NameID")

		attributes: dict[str, list[str]] = {}
		for attribute_statement in authn_response.assertion.attribute_statement:
			for attribute in attribute_statement.attribute:
				attributes.setdefault(attribute.name, []).extend(value.text for value in attribute.attribute_value if value.text)

		roles = [
			g.lower()
			for g in attributes.get("Role")
			or attributes.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
			or attributes.get("groupMembership")
			or []
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
		params = dict(request.query_params)
		if saml_logger.isEnabledFor(TRACE):
			saml_logger.trace("SAML Logout Callback Request query params: %s", params)

		if "SAMLResponse" in params:
			message_type = "SAMLResponse"
		elif "SAMLRequest" in params:
			message_type = "SAMLRequest"
		else:
			raise RuntimeError("SAML LogoutRequest/LogoutResponse not found. Only supported HTTP_REDIRECT Binding")

		error = None
		with saml_client() as client:
			# Like python3-saml: The signature is only checked if present
			if "Signature" in params:
				saml_msg = {
					message_type: params[message_type],
					"Signature": params["Signature"],
					"SigAlg": params.get("SigAlg", SIG_RSA_SHA1),
				}
				if "RelayState" in params:
					saml_msg["RelayState"] = params["RelayState"]
				assert client.metadata is not None
				certs = client.metadata.certs(config.saml_idp_entity_id, "any", "signing")
				if not any(verify_redirect_signature(saml_msg, RSACrypto(None), cert) for _cert_name, cert in certs):
					error = f"Invalid signature of {message_type}"

			if not error:
				if message_type == "SAMLResponse":
					message = await run_in_threadpool(client.parse_logout_request_response, params[message_type], BINDING_HTTP_REDIRECT)
				else:
					message = await run_in_threadpool(client.parse_logout_request, params[message_type], BINDING_HTTP_REDIRECT)
				if saml_logger.isEnabledFor(TRACE) and message:
					saml_logger.trace("SAML Logout Callback %s XML: %s", message_type, message.xmlstr)
				if not message or not message.verify():
					error = f"Invalid {message_type}"

		if error:
			saml_logger.error("Failed to process SAML SLO response: %s", error)
		else:
			saml_logger.info("SAML SLO successful")
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
