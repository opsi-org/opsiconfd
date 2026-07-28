# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.audit_log

RPC methods for reading and writing audit log entries.

Audit log entries are stored in the `AUDIT_LOG` table.
Event type specific details are stored in separate detail tables
(`AUDIT_AUTHENTICATION`, `AUDIT_PRODUCT_ACTION_REQUEST`) keyed by `auditLogId`.
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
	"""Mixin providing the auditLog RPC methods of the backend."""

	def _auditLog_to_object(self: BackendProtocol, auditLog: dict | AuditLog) -> AuditLog:
		"""Convert a dict to an `AuditLog` object, passing `AuditLog` instances through unchanged.

		Args:
			auditLog: Audit log entry as dict or `AuditLog` object.

		Returns:
			The `AuditLog` object.
		"""
		if isinstance(auditLog, AuditLog):
			return auditLog
		return AuditLog.fromHash({"type": "AuditLog", **auditLog})

	def _auditLog_validate(self: BackendProtocol, auditLog: AuditLog) -> None:
		"""Validate an `AuditLog` object before it is written to the database.

		Checks that the eventType is set and valid and that event type specific details
		(authentication, productActionRequest) are only present for matching event types.

		Args:
			auditLog: The `AuditLog` object to validate.

		Raises:
			ValueError: If the eventType is missing or invalid, if details are not allowed
				for the eventType or if required attributes for the eventType are missing.
		"""
		if not auditLog.eventType:
			raise ValueError("AuditLog eventType is required")
		if not isinstance(auditLog.eventType, AuditLogEventType) or auditLog.eventType == AuditLogEventType.UNKNOWN:
			raise ValueError(f"Invalid AuditLog eventType: {auditLog.eventType!r}")
		if auditLog.authentication and auditLog.eventType not in AUTHENTICATION_EVENT_TYPES:
			raise ValueError(f"AuditLog authentication is not allowed for eventType: {auditLog.eventType!r}")
		if auditLog.productActionRequest and auditLog.eventType != AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST:
			raise ValueError(f"AuditLog productActionRequest is not allowed for eventType: {auditLog.eventType!r}")
		if auditLog.eventType == AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST:
			if not auditLog.productActionRequest:
				raise ValueError(f"AuditLog productActionRequest is required for eventType: {auditLog.eventType!r}")
			if not auditLog.hostId:
				raise ValueError(f"AuditLog hostId is required for eventType: {auditLog.eventType!r}")

	def _auditLog_bulkInsertObjects(self: BackendProtocol, auditLogs: list[dict] | list[AuditLog]) -> None:
		"""Insert audit log entries in chunks using multi-row INSERT statements.

		Assigns the generated ids to the passed objects.
		Event type specific details are inserted into their detail tables.

		Args:
			auditLogs: Audit log entries to insert.

		Raises:
			ValueError: If an audit log entry fails validation.
			RuntimeError: If the generated ids cannot be determined after insert.
		"""
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
				for idx, audit_log in enumerate(chunk):
					values.append(
						f"(COALESCE(:created_{idx}, CURRENT_TIMESTAMP), :eventType_{idx}, :username_{idx}, :actorType_{idx}, :actorId_{idx}, "
						f":clientAddress_{idx}, :userAgent_{idx}, :hostId_{idx}, :message_{idx})"
					)
					params.update(
						{
							f"created_{idx}": audit_log.created,
							f"eventType_{idx}": audit_log.eventType,
							f"username_{idx}": audit_log.username,
							f"actorType_{idx}": audit_log.actorType,
							f"actorId_{idx}": audit_log.actorId,
							f"clientAddress_{idx}": audit_log.clientAddress,
							f"userAgent_{idx}": audit_log.userAgent,
							f"hostId_{idx}": audit_log.hostId,
							f"message_{idx}": audit_log.message,
						}
					)

				result = session.execute(
					"""
					INSERT INTO `AUDIT_LOG`
						(`created`, `eventType`, `username`, `actorType`, `actorId`, `clientAddress`, `userAgent`, `hostId`, `message`)
					VALUES
						"""
					+ ",".join(values),
					params=params,
				)
				first_audit_log_id = result.lastrowid  # ty: ignore[unresolved-attribute]
				if not first_audit_log_id:
					raise RuntimeError("Failed to determine first auditLogId after bulk insert")
				for idx, audit_log in enumerate(chunk):
					audit_log.setId(first_audit_log_id + idx)

				auth_values = []
				auth_params: dict[str, Any] = {}
				for idx, audit_log in enumerate(chunk):
					if not audit_log.authentication:
						continue
					auth_values.append(f"(:auditLogId_{idx}, :authMethods_{idx}, :failureReason_{idx}, :logoutReason_{idx})")
					auth_params.update(
						{
							f"auditLogId_{idx}": audit_log.id,
							f"authMethods_{idx}": dumps(audit_log.authentication.authMethods)
							if audit_log.authentication.authMethods is not None
							else None,
							f"failureReason_{idx}": audit_log.authentication.failureReason,
							f"logoutReason_{idx}": audit_log.authentication.logoutReason,
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
				for idx, audit_log in enumerate(chunk):
					product_action_request = audit_log.productActionRequest
					if not product_action_request:
						continue
					client_product_values.append(f"(:auditLogId_{idx}, :productId_{idx}, :actionRequest_{idx})")
					client_product_params.update(
						{
							f"auditLogId_{idx}": audit_log.id,
							f"productId_{idx}": product_action_request.productId,
							f"actionRequest_{idx}": product_action_request.actionRequest,
						}
					)

				if client_product_values:
					session.execute(
						"""
						INSERT INTO `AUDIT_PRODUCT_ACTION_REQUEST` (`auditLogId`, `productId`, `actionRequest`)
						VALUES
							"""
						+ ",".join(client_product_values),
						params=client_product_params,
					)

	def auditLog_bulkInsertObjects(self: BackendProtocol, auditLogs: list[dict] | list[AuditLog]) -> None:
		"""Insert a large number of audit log entries efficiently.

		Args:
			auditLogs: Audit log entries to insert.
		"""
		self._auditLog_bulkInsertObjects(auditLogs)

	def auditLog_createObjects(self: BackendProtocol, auditLogs: list[dict] | list[AuditLog] | dict | AuditLog) -> None:
		"""Create audit log entries.

		Each entry is validated and inserted individually together with its
		event type specific details. Any passed id is ignored, ids are generated by the database.

		Args:
			auditLogs: One or more audit log entries to create.

		Raises:
			ValueError: If an audit log entry fails validation.
			RuntimeError: If the generated id cannot be determined after insert.
		"""
		with self._mysql.session() as session:
			for audit_log in to_list(auditLogs):
				audit_log = self._auditLog_to_object(audit_log)
				self._auditLog_validate(audit_log)
				audit_log.id = None

				inserted_id = self._mysql.insert_object(
					table="AUDIT_LOG", obj=audit_log, ace=[], create=True, set_null=False, session=session
				)
				if not inserted_id:
					raise RuntimeError("Failed to determine auditLogId after insert")
				audit_log.setId(inserted_id)
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

				client_product_action_request = audit_log.productActionRequest
				if client_product_action_request:
					session.execute(
						"""
						INSERT INTO `AUDIT_PRODUCT_ACTION_REQUEST` (`auditLogId`, `productId`, `actionRequest`)
						VALUES (:auditLogId, :productId, :actionRequest)
						ON DUPLICATE KEY UPDATE
							`productId` = :productId,
							`actionRequest` = :actionRequest
						""",
						params={
							"auditLogId": audit_log.id,
							"productId": client_product_action_request.productId,
							"actionRequest": client_product_action_request.actionRequest,
						},
					)

	def auditLog_insertObject(self: BackendProtocol, auditLog: dict | AuditLog) -> None:
		"""Insert a single audit log entry.

		Args:
			auditLog: The audit log entry to insert.
		"""
		self.auditLog_createObjects(auditLog)

	def _auditLog_getObjects(
		self: BackendProtocol,
		ace: list[Any] | None = None,
		attributes: list[str] | None = None,
		filter: dict[str, Any] | None = None,
		orderBy: OrderBy | None = None,
		limit: int | None = None,
	) -> list[AuditLog]:
		"""Fetch audit log entries and hydrate event type specific details.

		Detail tables are only queried for entries whose eventType can have matching detail rows.

		Args:
			ace: Access control entries to apply.
			attributes: `AUDIT_LOG` attributes to select, `None` or `[]` selects all attributes.
			filter: Mapping of `AUDIT_LOG` attribute names to match values, `None` selects all entries.
				Conditions on different attributes are AND-combined.
				A value can be a single value or a list of values, which are OR-combined.
				String values may contain wildcards (`*` matches any sequence of characters)
				or start with a comparison operator (`<`, `<=`, `=`, `>=` or `>`),
				e.g. `{"created": ">=2026-01-01"}`. Without an operator `=` is used.
				Attributes with the value `None` are ignored, unknown attributes raise a `ValueError`.
			orderBy: Mapping of attribute names to a sort direction (`"asc"` or `"desc"`, case-insensitive),
				e.g. `{"created": "desc", "username": "asc"}`.
				Entries are sorted by the attributes in the given order.
				Accepts `AUDIT_LOG` attributes and authentication detail attributes
				(`authMethods`, `failureReason`, `logoutReason`).
				Unknown attributes or invalid directions raise a `ValueError`.
			limit: Maximum number of entries to return.

		Returns:
			The matching `AuditLog` objects.
		"""
		table = "AUDIT_LOG"
		if orderBy and AUDIT_LOG_AUTHENTICATION_ATTRIBUTES.intersection(orderBy):
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

		# Detail tables are bound to specific eventTypes, query them only for ids that can have matching rows.
		# An eventType of None (not selected via attributes) is treated as a possible match.
		authentication_ids = [
			id
			for id, audit_log in audit_log_by_id.items()
			if audit_log.eventType is None or audit_log.eventType in AUTHENTICATION_EVENT_TYPES
		]
		product_action_request_ids = [
			id
			for id, audit_log in audit_log_by_id.items()
			if audit_log.eventType is None or audit_log.eventType == AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST
		]
		if not authentication_ids and not product_action_request_ids:
			return audit_logs

		with self._mysql.session() as session:
			if authentication_ids:
				rows = session.execute(
					"SELECT `auditLogId`, `authMethods`, `failureReason`, `logoutReason` FROM `AUDIT_AUTHENTICATION` WHERE `auditLogId` IN :ids",
					params={"ids": authentication_ids},
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

			if product_action_request_ids:
				rows = session.execute(
					"SELECT `auditLogId`, `productId`, `actionRequest` FROM `AUDIT_PRODUCT_ACTION_REQUEST` WHERE `auditLogId` IN :ids",
					params={"ids": product_action_request_ids},
				).fetchall()
				for row in rows:
					row_dict = dict(row)
					audit_log_by_id[str(row_dict["auditLogId"])].setProductActionRequest(
						{
							"productId": row_dict["productId"],
							"actionRequest": row_dict["actionRequest"],
						}
					)
		return audit_logs

	@rpc_method(check_acl=False)
	def auditLog_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		filter: dict[str, Any] | None = None,
		orderBy: OrderBy | None = None,
		limit: int | None = None,
	) -> list[AuditLog]:
		"""Get audit log entries including their event type specific details.

		Args:
			attributes: `AUDIT_LOG` attributes to select, `None` or `[]` selects all attributes.
			filter: Mapping of `AUDIT_LOG` attribute names to match values, `None` selects all entries.
				Conditions on different attributes are AND-combined.
				A value can be a single value or a list of values, which are OR-combined.
				String values may contain wildcards (`*` matches any sequence of characters)
				or start with a comparison operator (`<`, `<=`, `=`, `>=` or `>`),
				e.g. `{"created": ">=2026-01-01"}`. Without an operator `=` is used.
				Attributes with the value `None` are ignored, unknown attributes raise a `ValueError`.
			orderBy: Mapping of attribute names to a sort direction (`"asc"` or `"desc"`, case-insensitive),
				e.g. `{"created": "desc", "username": "asc"}`.
				Entries are sorted by the attributes in the given order.
				Accepts `AUDIT_LOG` attributes and authentication detail attributes
				(`authMethods`, `failureReason`, `logoutReason`).
				Unknown attributes or invalid directions raise a `ValueError`.
			limit: Maximum number of entries to return.

		Returns:
			The matching `AuditLog` objects.
		"""
		ace = self._get_ace("auditLog_getObjects")
		return self._auditLog_getObjects(
			ace=ace,
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
		"""Get the idents of matching audit log entries.

		Args:
			returnType: Format of the returned idents ("str", "dict", "list" or "tuple").
			**filter: `AUDIT_LOG` attribute names with match values as keyword arguments.
				Conditions on different attributes are AND-combined.
				A value can be a single value or a list of values, which are OR-combined.
				String values may contain wildcards (`*` matches any sequence of characters)
				or start with a comparison operator (`<`, `<=`, `=`, `>=` or `>`),
				e.g. `created=">=2026-01-01"`. Without an operator `=` is used.
				Attributes with the value `None` are ignored, unknown attributes raise a `ValueError`.

		Returns:
			The idents of the matching audit log entries in the requested format.
		"""
		ace = self._get_ace("auditLog_getObjects")
		objects = self._mysql.get_objects(
			table="AUDIT_LOG", object_type=AuditLog, return_type="dict", ace=ace, attributes=["id"], filter=filter
		)
		idents = [self._mysql.get_ident(data=audit_log, ident_attributes=("id",), ident_type=returnType) for audit_log in objects]
		return cast(list[str] | list[dict] | list[list] | list[tuple], idents)
