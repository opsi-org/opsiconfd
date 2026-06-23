# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.audit_log
"""

from __future__ import annotations

from json import dumps, loads
from typing import TYPE_CHECKING, Any, Protocol, cast

from opsi.opsi.service.model.object import AuditLog, AuditLogEventType
from opsi.opsi.service.model.type import to_list

from . import rpc_method

if TYPE_CHECKING:
	from ..mysql import OrderBy
	from .protocol import BackendProtocol, IdentType

AUDIT_LOG_AUTHENTICATION_ATTRIBUTES = {"authMethods", "failureReason", "logoutReason"}
AUTHENTICATION_EVENT_TYPES = {
	AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
	AuditLogEventType.AUTHENTICATION_LOGIN_FAILED,
	AuditLogEventType.AUTHENTICATION_LOGOUT,
}


class RPCAuditLogMixin(Protocol):
	def _auditLog_to_object(self: BackendProtocol, auditLog: dict | AuditLog) -> AuditLog:
		if isinstance(auditLog, AuditLog):
			return auditLog
		return AuditLog.fromHash({"type": "AuditLog", **auditLog})

	def _auditLog_validate(self: BackendProtocol, auditLog: AuditLog) -> None:
		if not auditLog.eventType:
			raise ValueError("AuditLog eventType is required")
		if not isinstance(auditLog.eventType, AuditLogEventType) or auditLog.eventType == AuditLogEventType.UNKNOWN:
			raise ValueError(f"Invalid AuditLog eventType: {auditLog.eventType!r}")
		if auditLog.authentication and auditLog.eventType not in AUTHENTICATION_EVENT_TYPES:
			raise ValueError(f"AuditLog authentication is not allowed for eventType: {auditLog.eventType!r}")
		if auditLog.clientProductActionRequest and auditLog.eventType != AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST:
			raise ValueError(f"AuditLog clientProductActionRequest is not allowed for eventType: {auditLog.eventType!r}")
		if auditLog.eventType == AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST and not auditLog.clientProductActionRequest:
			raise ValueError(f"AuditLog clientProductActionRequest is required for eventType: {auditLog.eventType!r}")

	def _auditLog_bulkInsertObjects(self: BackendProtocol, auditLogs: list[dict] | list[AuditLog]) -> None:
		audit_logs = [self._auditLog_to_object(audit_log) for audit_log in auditLogs]
		if not audit_logs:
			return

		for audit_log in audit_logs:
			self._auditLog_validate(audit_log)
			audit_log.id = None

		chunk_size = 1000
		with self._mysql.session() as session:
			for offset in range(0, len(audit_logs), chunk_size):
				chunk = audit_logs[offset : offset + chunk_size]
				values = []
				params: dict[str, Any] = {}
				for index, audit_log in enumerate(chunk):
					values.append(
						"(COALESCE(:created_{0}, CURRENT_TIMESTAMP), :eventType_{0}, :username_{0}, :actorType_{0}, "
						":actorId_{0}, :clientAddress_{0}, :userAgent_{0}, :message_{0})".format(index)
					)
					params.update(
						{
							f"created_{index}": audit_log.created,
							f"eventType_{index}": audit_log.eventType,
							f"username_{index}": audit_log.username,
							f"actorType_{index}": audit_log.actorType,
							f"actorId_{index}": audit_log.actorId,
							f"clientAddress_{index}": audit_log.clientAddress,
							f"userAgent_{index}": audit_log.userAgent,
							f"message_{index}": audit_log.message,
						}
					)

				result = session.execute(
					"""
					INSERT INTO `AUDIT_LOG`
						(`created`, `eventType`, `username`, `actorType`, `actorId`, `clientAddress`, `userAgent`, `message`)
					VALUES
						"""
					+ ",".join(values),
					params=params,
				)
				first_audit_log_id = result.lastrowid  # ty: ignore[unresolved-attribute]
				if not first_audit_log_id:
					raise RuntimeError("Failed to determine first auditLogId after bulk insert")
				for index, audit_log in enumerate(chunk):
					audit_log.setId(first_audit_log_id + index)

				auth_values = []
				auth_params: dict[str, Any] = {}
				for index, audit_log in enumerate(chunk):
					if not audit_log.authentication:
						continue
					auth_values.append(f"(:auditLogId_{index}, :authMethods_{index}, :failureReason_{index}, :logoutReason_{index})")
					auth_params.update(
						{
							f"auditLogId_{index}": audit_log.id,
							f"authMethods_{index}": dumps(audit_log.authentication.authMethods)
							if audit_log.authentication.authMethods is not None
							else None,
							f"failureReason_{index}": audit_log.authentication.failureReason,
							f"logoutReason_{index}": audit_log.authentication.logoutReason,
						}
					)

				if auth_values:
					session.execute(
						"""
						INSERT INTO `AUDIT_AUTHENTICATION` (`auditLogId`, `authMethods`, `failureReason`, `logoutReason`)
						VALUES
							"""
						+ ",".join(auth_values),
						params=auth_params,
					)

				client_product_values = []
				client_product_params: dict[str, Any] = {}
				for index, audit_log in enumerate(chunk):
					client_product_action_request = audit_log.clientProductActionRequest
					if not client_product_action_request:
						continue
					client_product_values.append(f"(:auditLogId_{index}, :productId_{index}, :clientId_{index}, :actionRequest_{index})")
					client_product_params.update(
						{
							f"auditLogId_{index}": audit_log.id,
							f"productId_{index}": client_product_action_request.productId,
							f"clientId_{index}": client_product_action_request.clientId,
							f"actionRequest_{index}": client_product_action_request.actionRequest,
						}
					)

				if client_product_values:
					session.execute(
						"""
						INSERT INTO `AUDIT_CLIENT_PRODUCT_ACTION_REQUEST` (`auditLogId`, `productId`, `clientId`, `actionRequest`)
						VALUES
							"""
						+ ",".join(client_product_values),
						params=client_product_params,
					)

	def auditLog_bulkInsertObjects(self: BackendProtocol, auditLogs: list[dict] | list[AuditLog]) -> None:
		self._auditLog_bulkInsertObjects(auditLogs)

	def auditLog_createObjects(self: BackendProtocol, auditLogs: list[dict] | list[AuditLog] | dict | AuditLog) -> None:
		with self._mysql.session() as session:
			for audit_log in to_list(auditLogs):
				audit_log = self._auditLog_to_object(audit_log)
				self._auditLog_validate(audit_log)
				audit_log.id = None

				inserted_id = self._mysql.insert_object(
					table="AUDIT_LOG", obj=audit_log, ace=[], create=True, set_null=False, session=session
				)
				if inserted_id:
					audit_log.setId(inserted_id)
				if not audit_log.id:
					raise RuntimeError("Failed to determine auditLogId after insert")
				if audit_log.authentication:
					session.execute(
						"""
						INSERT INTO `AUDIT_AUTHENTICATION` (`auditLogId`, `authMethods`, `failureReason`, `logoutReason`)
						VALUES (:auditLogId, :authMethods, :failureReason, :logoutReason)
						ON DUPLICATE KEY UPDATE
							`authMethods` = :authMethods,
							`failureReason` = :failureReason,
							`logoutReason` = :logoutReason
						""",
						params={
							"auditLogId": audit_log.id,
							"authMethods": dumps(audit_log.authentication.authMethods)
							if audit_log.authentication.authMethods is not None
							else None,
							"failureReason": audit_log.authentication.failureReason,
							"logoutReason": audit_log.authentication.logoutReason,
						},
					)

				client_product_action_request = audit_log.clientProductActionRequest
				if client_product_action_request:
					session.execute(
						"""
						INSERT INTO `AUDIT_CLIENT_PRODUCT_ACTION_REQUEST` (`auditLogId`, `productId`, `clientId`, `actionRequest`)
						VALUES (:auditLogId, :productId, :clientId, :actionRequest)
						ON DUPLICATE KEY UPDATE
							`productId` = :productId,
							`clientId` = :clientId,
							`actionRequest` = :actionRequest
						""",
						params={
							"auditLogId": audit_log.id,
							"productId": client_product_action_request.productId,
							"clientId": client_product_action_request.clientId,
							"actionRequest": client_product_action_request.actionRequest,
						},
					)

	def auditLog_insertObject(self: BackendProtocol, auditLog: dict | AuditLog) -> None:
		self.auditLog_createObjects(auditLog)

	def _auditLog_getObjects(
		self: BackendProtocol,
		ace: list[Any] | None = None,
		withAuthentication: bool = True,
		withClientProductActionRequest: bool = True,
		attributes: list[str] | None = None,
		filter: dict[str, Any] | None = None,
		orderBy: OrderBy | None = None,
		limit: int | None = None,
	) -> list[AuditLog]:
		table = "AUDIT_LOG"
		if withAuthentication and orderBy and AUDIT_LOG_AUTHENTICATION_ATTRIBUTES.intersection(orderBy):
			table = "AUDIT_LOG LEFT JOIN AUDIT_AUTHENTICATION USING(auditLogId)"

		audit_logs = self._mysql.get_objects(
			table=table,
			ace=ace,
			object_type=AuditLog,
			attributes=attributes,
			filter=filter,
			order_by=orderBy,
			limit=limit,
		)
		if not audit_logs:
			return audit_logs

		audit_log_by_id = {audit_log.id: audit_log for audit_log in audit_logs if audit_log.id is not None}
		if not audit_log_by_id:
			return audit_logs

		ids = list(audit_log_by_id)
		with self._mysql.session() as session:
			if withAuthentication:
				rows = session.execute(
					"SELECT `auditLogId`, `authMethods`, `failureReason`, `logoutReason` FROM `AUDIT_AUTHENTICATION` WHERE `auditLogId` IN :ids",
					params={"ids": ids},
				).fetchall()

				for row in rows:
					row_dict = dict(row)
					auth_methods = row_dict["authMethods"]
					audit_log_by_id[str(row_dict["auditLogId"])].setAuthentication(
						{
							"authMethods": loads(auth_methods) if auth_methods is not None else None,
							"failureReason": row_dict["failureReason"],
							"logoutReason": row_dict["logoutReason"],
						}
					)

			if withClientProductActionRequest:
				rows = session.execute(
					"SELECT `auditLogId`, `productId`, `clientId`, `actionRequest` FROM `AUDIT_CLIENT_PRODUCT_ACTION_REQUEST` WHERE `auditLogId` IN :ids",
					params={"ids": ids},
				).fetchall()
				for row in rows:
					row_dict = dict(row)
					audit_log_by_id[str(row_dict["auditLogId"])].setClientProductActionRequest(
						{
							"productId": row_dict["productId"],
							"clientId": row_dict["clientId"],
							"actionRequest": row_dict["actionRequest"],
						}
					)
		return audit_logs

	@rpc_method(check_acl=False)
	def auditLog_getObjects(
		self: BackendProtocol,
		withAuthentication: bool = True,
		withClientProductActionRequest: bool = True,
		attributes: list[str] | None = None,
		filter: dict[str, Any] | None = None,
		orderBy: OrderBy | None = None,
		limit: int | None = None,
	) -> list[AuditLog]:
		ace = self._get_ace("auditLog_getObjects")
		return self._auditLog_getObjects(
			ace=ace,
			withAuthentication=withAuthentication,
			withClientProductActionRequest=withClientProductActionRequest,
			attributes=attributes,
			filter=filter,
			orderBy=orderBy,
			limit=limit,
		)

	@rpc_method(check_acl=False)
	def auditLog_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("auditLog_getObjects")
		objects = self._mysql.get_objects(
			table="AUDIT_LOG", object_type=AuditLog, return_type="dict", ace=ace, attributes=["id"], filter=filter
		)
		idents = [self._mysql.get_ident(data=audit_log, ident_attributes=("id",), ident_type=returnType) for audit_log in objects]
		return cast(list[str] | list[dict] | list[list] | list[tuple], idents)
