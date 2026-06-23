# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.obj_audit_log
"""

import pytest
from opsi.opsi.service.model.object import (
	AuditLog,
	AuditLogAuthentication,
	AuditLogAuthenticationFailureReason,
	AuditLogAuthenticationLogoutReason,
	AuditLogClientProductActionRequest,
	AuditLogEventType,
)

from opsiconfd.backend.mysql import MySQLSession
from tests.utils import UnprotectedBackend, backend, clean_mysql, clean_redis  # noqa: F401


def test_audit_log_object() -> None:
	audit_log = AuditLog(
		eventType=AuditLogEventType.AUTHENTICATION_LOGIN_FAILED,
		username="adminuser",
		authentication={
			"authMethods": ["password", "totp"],
			"failureReason": AuditLogAuthenticationFailureReason.INVALID_CREDENTIALS,
			"futureAttribute": "ignored",
		},
	)

	assert isinstance(audit_log.authentication, AuditLogAuthentication)
	assert audit_log.authentication.authMethods == ["password", "totp"]
	assert audit_log.to_hash()["authentication"] == {
		"authMethods": ["password", "totp"],
		"failureReason": AuditLogAuthenticationFailureReason.INVALID_CREDENTIALS,
		"logoutReason": None,
	}
	assert "futureAttribute" not in audit_log.to_hash()["authentication"]


def test_audit_log_client_product_action_request_object() -> None:
	audit_log = AuditLog(
		eventType=AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST,
		clientProductActionRequest={
			"productId": "test-product",
			"clientId": "test-client.opsi.test",
			"actionRequest": "setup",
			"futureAttribute": "ignored",
		},
	)

	assert isinstance(audit_log.clientProductActionRequest, AuditLogClientProductActionRequest)
	assert audit_log.clientProductActionRequest.productId == "test-product"
	assert audit_log.clientProductActionRequest.clientId == "test-client.opsi.test"
	assert audit_log.clientProductActionRequest.actionRequest == "setup"
	assert audit_log.to_hash()["clientProductActionRequest"] == {
		"productId": "test-product",
		"clientId": "test-client.opsi.test",
		"actionRequest": "setup",
	}
	assert "futureAttribute" not in audit_log.to_hash()["clientProductActionRequest"]


def test_audit_log_accepts_unknown_event_type_for_client_compatibility() -> None:
	audit_log = AuditLog(eventType="future.event", authentication={"futureAttribute": "ignored"})

	assert audit_log.eventType == AuditLogEventType.UNKNOWN
	assert audit_log.authentication == AuditLogAuthentication()


def test_audit_log_rpc_methods(backend: UnprotectedBackend) -> None:  # noqa: F811
	assert hasattr(backend, "auditLog_bulkInsertObjects")
	assert hasattr(backend, "auditLog_insertObject")
	assert hasattr(backend, "auditLog_getObjects")
	assert hasattr(backend, "auditLog_getIdents")
	assert not hasattr(backend, "auditLog_updateObjects")
	assert not hasattr(backend, "auditLog_deleteObjects")


def test_audit_log_create_and_get_objects(backend: UnprotectedBackend) -> None:  # noqa: F811
	audit_log = AuditLog(
		id=12345,
		eventType=AuditLogEventType.AUTHENTICATION_LOGIN_FAILED,
		username="adminuser",
		actorType="user",
		actorId="adminuser",
		clientAddress="192.0.2.10",
		userAgent="test-agent",
		message="Login failed",
		authentication=AuditLogAuthentication(
			authMethods=["password"], failureReason=AuditLogAuthenticationFailureReason.INVALID_CREDENTIALS
		),
	)

	backend.auditLog_bulkInsertObjects([audit_log])  # ty: ignore[invalid-argument-type]
	assert audit_log.id is not None
	assert audit_log.id != 12345

	audit_logs = backend.auditLog_getObjects(filter={"id": audit_log.id})
	assert len(audit_logs) == 1
	stored_log = audit_logs[0]
	assert isinstance(stored_log, AuditLog)
	assert stored_log.id == audit_log.id
	assert stored_log.eventType == AuditLogEventType.AUTHENTICATION_LOGIN_FAILED
	assert stored_log.username == "adminuser"
	assert stored_log.authentication == AuditLogAuthentication(
		authMethods=["password"], failureReason=AuditLogAuthenticationFailureReason.INVALID_CREDENTIALS
	)

	idents = backend.auditLog_getIdents(returnType="dict", eventType=AuditLogEventType.AUTHENTICATION_LOGIN_FAILED)
	assert idents == [{"id": audit_log.id}]


def test_audit_log_insert_object(backend: UnprotectedBackend) -> None:  # noqa: F811
	audit_log = AuditLog(
		eventType=AuditLogEventType.AUTHENTICATION_LOGIN_FAILED,
		username="adminuser",
		authentication=AuditLogAuthentication(
			authMethods=["password"], failureReason=AuditLogAuthenticationFailureReason.INVALID_CREDENTIALS
		),
	)

	backend.auditLog_insertObject(audit_log)  # ty: ignore[invalid-argument-type]

	audit_logs = backend.auditLog_getObjects(filter={"id": audit_log.id})
	assert len(audit_logs) == 1
	assert audit_logs[0].authentication == AuditLogAuthentication(
		authMethods=["password"], failureReason=AuditLogAuthenticationFailureReason.INVALID_CREDENTIALS
	)


def test_audit_log_bulk_insert_objects(backend: UnprotectedBackend) -> None:  # noqa: F811
	backend.auditLog_bulkInsertObjects(  # ty: ignore[invalid-argument-type]
		[
			{"eventType": AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED, "username": "user1"},
			{
				"eventType": AuditLogEventType.AUTHENTICATION_LOGOUT,
				"username": "user1",
				"authentication": {"logoutReason": AuditLogAuthenticationLogoutReason.USER_REQUESTED},
			},
		]
	)

	audit_logs = backend.auditLog_getObjects(filter={"username": "user1"})
	assert [audit_log.eventType for audit_log in audit_logs] == [
		AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
		AuditLogEventType.AUTHENTICATION_LOGOUT,
	]
	assert audit_logs[0].authentication is None
	assert audit_logs[1].authentication == AuditLogAuthentication(logoutReason=AuditLogAuthenticationLogoutReason.USER_REQUESTED)


def test_audit_log_client_product_action_request_create_and_get_objects(backend: UnprotectedBackend) -> None:  # noqa: F811
	audit_log = AuditLog(
		eventType=AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST,
		username="adminuser",
		clientProductActionRequest=AuditLogClientProductActionRequest(
			productId="test-product",
			clientId="test-client.opsi.test",
			actionRequest="setup",
		),
	)

	backend.auditLog_bulkInsertObjects([audit_log])  # ty: ignore[invalid-argument-type]

	audit_logs = backend.auditLog_getObjects(filter={"id": audit_log.id})
	assert len(audit_logs) == 1
	assert audit_logs[0].clientProductActionRequest == AuditLogClientProductActionRequest(
		productId="test-product",
		clientId="test-client.opsi.test",
		actionRequest="setup",
	)


def test_audit_log_bulk_insert_objects_uses_multirow_insert(backend: UnprotectedBackend) -> None:  # noqa: F811
	insert_counts = {"AUDIT_LOG": 0, "AUDIT_AUTHENTICATION": 0, "AUDIT_CLIENT_PRODUCT_ACTION_REQUEST": 0}

	def query_log(*args: object) -> None:
		statement = str(args[2])
		for table in insert_counts:
			if f"INSERT INTO `{table}`" in statement:
				insert_counts[table] += 1

	audit_logs = [
		AuditLog(
			eventType=AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
			username=f"user{index}",
			authentication=AuditLogAuthentication(authMethods=["password"]) if index % 2 else None,
		)
		for index in range(1200)
	]

	old_query_log = MySQLSession.query_log
	MySQLSession.query_log = query_log
	try:
		backend.auditLog_bulkInsertObjects(audit_logs)  # ty: ignore[invalid-argument-type]
	finally:
		MySQLSession.query_log = old_query_log

	assert insert_counts == {"AUDIT_LOG": 2, "AUDIT_AUTHENTICATION": 2, "AUDIT_CLIENT_PRODUCT_ACTION_REQUEST": 0}
	assert all(audit_log.id for audit_log in audit_logs)
	assert len(backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED})) == 1200


def test_audit_log_bulk_insert_client_product_action_request_uses_multirow_insert(backend: UnprotectedBackend) -> None:  # noqa: F811
	insert_counts = {"AUDIT_LOG": 0, "AUDIT_CLIENT_PRODUCT_ACTION_REQUEST": 0}

	def query_log(*args: object) -> None:
		statement = str(args[2])
		for table in insert_counts:
			if f"INSERT INTO `{table}`" in statement:
				insert_counts[table] += 1

	audit_logs = [
		AuditLog(
			eventType=AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST,
			username="adminuser",
			clientProductActionRequest=AuditLogClientProductActionRequest(
				productId="test-product",
				clientId=f"test-client-{index}.opsi.test",
				actionRequest="setup",
			),
		)
		for index in range(1200)
	]

	old_query_log = MySQLSession.query_log
	MySQLSession.query_log = query_log
	try:
		backend.auditLog_bulkInsertObjects(audit_logs)  # ty: ignore[invalid-argument-type]
	finally:
		MySQLSession.query_log = old_query_log

	assert insert_counts == {"AUDIT_LOG": 2, "AUDIT_CLIENT_PRODUCT_ACTION_REQUEST": 2}
	assert all(audit_log.id for audit_log in audit_logs)
	assert len(backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST})) == 1200


def test_audit_log_get_objects_orders_and_limits(backend: UnprotectedBackend) -> None:  # noqa: F811
	backend.auditLog_bulkInsertObjects(  # ty: ignore[invalid-argument-type]
		[
			{
				"created": "2026-01-01 00:00:00",
				"eventType": AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
				"username": "order-limit-user-1",
			},
			{
				"created": "2026-01-02 00:00:00",
				"eventType": AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
				"username": "order-limit-user-2",
			},
			{
				"created": "2026-01-03 00:00:00",
				"eventType": AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
				"username": "order-limit-user-3",
			},
		]
	)

	audit_logs = backend.auditLog_getObjects(
		filter={"username": "order-limit-user-*"},
		orderBy={"created": "desc"},
		limit=2,
	)

	assert [audit_log.username for audit_log in audit_logs] == ["order-limit-user-3", "order-limit-user-2"]


def test_audit_log_get_objects_orders_by_authentication_attribute(backend: UnprotectedBackend) -> None:  # noqa: F811
	backend.auditLog_bulkInsertObjects(  # ty: ignore[invalid-argument-type]
		[
			{
				"eventType": AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
				"username": "auth-order-user-password",
				"authentication": {"authMethods": ["password"]},
			},
			{
				"eventType": AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
				"username": "auth-order-user-saml",
				"authentication": {"authMethods": ["saml"]},
			},
		]
	)

	audit_logs = backend.auditLog_getObjects(
		filter={"username": "auth-order-user-*"},
		orderBy={"authMethods": "desc"},
	)

	assert [audit_log.username for audit_log in audit_logs] == ["auth-order-user-saml", "auth-order-user-password"]


def test_audit_log_create_requires_event_type(backend: UnprotectedBackend) -> None:  # noqa: F811
	with pytest.raises(ValueError, match="eventType is required"):
		backend.auditLog_bulkInsertObjects([AuditLog(username="adminuser")])  # ty: ignore[invalid-argument-type]


def test_audit_log_bulk_insert_rejects_invalid_event_type(backend: UnprotectedBackend) -> None:  # noqa: F811
	audit_log = AuditLog(eventType=AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED)
	audit_log.eventType = AuditLogEventType.UNKNOWN

	with pytest.raises(ValueError, match="Invalid AuditLog eventType"):
		backend.auditLog_bulkInsertObjects([audit_log])  # ty: ignore[invalid-argument-type]


def test_audit_log_bulk_insert_rejects_authentication_for_unknown_event(backend: UnprotectedBackend) -> None:  # noqa: F811
	audit_log = AuditLog(eventType=AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED, authentication={"authMethods": ["password"]})
	audit_log.eventType = AuditLogEventType.UNKNOWN

	with pytest.raises(ValueError, match="Invalid AuditLog eventType"):
		backend.auditLog_bulkInsertObjects([audit_log])  # ty: ignore[invalid-argument-type]


def test_audit_log_rejects_client_product_action_request_for_wrong_event_type(backend: UnprotectedBackend) -> None:  # noqa: F811
	audit_log = AuditLog(
		eventType=AuditLogEventType.AUTHENTICATION_LOGIN_SUCCEEDED,
		clientProductActionRequest={"productId": "test-product", "clientId": "test-client.opsi.test", "actionRequest": "setup"},
	)

	with pytest.raises(ValueError, match="clientProductActionRequest is not allowed"):
		backend.auditLog_bulkInsertObjects([audit_log])  # ty: ignore[invalid-argument-type]


def test_audit_log_requires_client_product_action_request_for_event_type(backend: UnprotectedBackend) -> None:  # noqa: F811
	audit_log = AuditLog(eventType=AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST)

	with pytest.raises(ValueError, match="clientProductActionRequest is required"):
		backend.auditLog_bulkInsertObjects([audit_log])  # ty: ignore[invalid-argument-type]
