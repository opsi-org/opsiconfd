# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

from functools import lru_cache
from typing import TYPE_CHECKING

from opsi.opsi.service.model.object import (
	AuditLog,
	AuditLogAuthentication,
	AuditLogAuthenticationFailureReason,
	AuditLogAuthenticationLogoutReason,
	AuditLogEventType,
)

from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.utils.modules import module_available

if TYPE_CHECKING:
	from starlette.types import Scope

	from opsiconfd.session import OPSISession


@lru_cache
def get_unprotected_backend():
	from opsiconfd.backend import get_unprotected_backend as get_unprotected_backend_impl

	return get_unprotected_backend_impl()


@lru_cache(maxsize=128)
def audit_log_event_enabled(event_type: AuditLogEventType) -> bool:

	if not module_available("audit_log"):
		return False
	if not config.audit_log_events:
		return False
	return event_type.value in config.audit_log_events


def _audit_auth_methods(session: OPSISession) -> list[str] | None:
	if not session.auth_methods:
		return None
	return sorted(str(method) for method in session.auth_methods)


async def audit_authentication_event(
	scope: Scope,
	event_type: AuditLogEventType,
	failure_reason: AuditLogAuthenticationFailureReason | None = None,
	logout_reason: AuditLogAuthenticationLogoutReason | None = None,
) -> None:
	if not audit_log_event_enabled(event_type):
		return
	try:
		session: OPSISession | None = scope.get("session")
		username = session.username if session else None
		actor_type = session.user_type if session else None
		message = None
		if event_type == AuditLogEventType.AUTHENTICATION_LOGIN_FAILED:
			message = "Authentication failed"
			if username:
				message += f" for user {username!r}"
		elif event_type == AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED:
			message = f"Authentication succeeded for user {username!r}"
		elif event_type == AuditLogEventType.AUTHENTICATION_LOGOUT:
			message = f"User {username!r} logged out"

		audit_log = AuditLog(
			eventType=event_type,
			username=username,
			actorType=actor_type,
			actorId=username,
			clientAddress=session.client_addr if session else None,
			userAgent=session.user_agent if session and session.user_agent else None,
			message=message,
			authentication=AuditLogAuthentication(
				authMethods=_audit_auth_methods(session)
				if session and event_type == AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED
				else None,
				failureReason=failure_reason,
				logoutReason=logout_reason,
			),
		)
		await get_unprotected_backend().async_call("auditLog_createObjects", auditLogs=[audit_log])
	except Exception as err:
		logger.error("Failed to write authentication audit log: %s", err, exc_info=True)


async def audit_terminal_event(
	session: OPSISession,
	event_type: AuditLogEventType,
	host_id: str,
	terminal_id: str,
) -> None:
	"""Write an audit log entry for a terminal lifecycle event.

	Args:
		session: Session of the user who initiated the terminal request.
		event_type: Terminal audit event type.
		host_id: Target client or server host id.
		terminal_id: Messagebus terminal id.
	"""
	if not audit_log_event_enabled(event_type):
		return
	try:
		username = session.username
		action = "opened" if event_type in (AuditLogEventType.CLIENT_TERMINAL_OPEN, AuditLogEventType.SERVER_TERMINAL_OPEN) else "closed"
		target_type = "client" if event_type in (AuditLogEventType.CLIENT_TERMINAL_OPEN, AuditLogEventType.CLIENT_TERMINAL_CLOSE) else "server"
		audit_log = AuditLog(
			eventType=event_type,
			username=username,
			actorType=session.user_type,
			actorId=username,
			clientAddress=session.client_addr,
			userAgent=session.user_agent if session.user_agent else None,
			hostId=host_id,
			message=f"Terminal {terminal_id!r} {action} on {target_type} {host_id!r}",
		)
		await get_unprotected_backend().async_call("auditLog_createObjects", auditLogs=[audit_log])
	except Exception as err:
		logger.error("Failed to write terminal audit log: %s", err, exc_info=True)
