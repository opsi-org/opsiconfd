# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.obj_user
"""

import time
from collections.abc import Generator
from pathlib import Path

import pytest
from opsi.opsi.service.model.object import AuditLog, AuditLogAuthenticationLogoutReason, AuditLogEventType, User

from opsiconfd.backend.rpc.main import ProtectedBackend
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	default_acl,
	get_config,
	test_client,
)

AGENT_PASSWORD = "Secret123!"


def _create_agent(test_client: OpsiconfdTestClient, user_id: str) -> None:  # noqa: F811
	test_client.reset_cookies()
	res = test_client.post(
		"/admin/create-user", auth=(ADMIN_USER, ADMIN_PASS), json={"user_id": user_id, "password": AGENT_PASSWORD, "agent": True}
	)
	assert res.status_code == 200
	test_client.reset_cookies()


def _rpc(test_client: OpsiconfdTestClient, method: str, auth: tuple[str, str]) -> dict:  # noqa: F811
	test_client.auth = auth
	return test_client.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).json()


def _wait_for_logout_audit_logs(backend: UnprotectedBackend, timeout: float = 10) -> list[AuditLog]:  # noqa: F811
	deadline = time.time() + timeout
	while time.time() < deadline:
		audit_logs = backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.AUTHENTICATION_LOGOUT})
		if audit_logs:
			return audit_logs
		time.sleep(0.2)
	return []


@pytest.fixture()
def user_delete_self_for_all(tmp_path: Path) -> Generator[None]:
	# Allow everyone, only the role check of the method protects it
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text("user_deleteSelf : all\n", encoding="utf-8")
	protected_backend = ProtectedBackend()
	try:
		with get_config({"acl_file": str(acl_file)}):
			protected_backend._read_acl_file()
			yield
	finally:
		protected_backend._read_acl_file()


@pytest.mark.parametrize(
	"description, expected",
	[
		(None, None),
		("", None),
		("Build server agent", "Build server agent"),
		("x" * 255, "x" * 255),
	],
)
def test_user_description_create_and_get(backend: UnprotectedBackend, description: str | None, expected: str | None) -> None:  # noqa: F811
	user_id = "test-user-description"
	try:
		backend.user_createObjects([User(id=user_id, description=description)])

		users = backend.user_getObjects(id=user_id)
		assert len(users) == 1
		assert users[0].description == expected

		users = backend.user_getObjects(attributes=["description"], id=user_id)
		assert len(users) == 1
		assert users[0].description == expected
	finally:
		backend.user_delete(user_id)


def test_user_bulk_insert_without_description(backend: UnprotectedBackend) -> None:  # noqa: F811
	# Objects from backups created before the attribute existed have no description
	user_ids = ["test-user-backup-1", "test-user-backup-2"]
	try:
		backend.user_bulkInsertObjects(  # ty: ignore[invalid-argument-type]
			[
				{"type": "User", "id": user_ids[0], "groups": ["opsiadmin"]},
				{"type": "User", "id": user_ids[1], "groups": [], "description": "Restored"},
			]
		)
		users = {user.id: user for user in backend.user_getObjects(id=user_ids)}
		assert users[user_ids[0]].description is None
		assert users[user_ids[1]].description == "Restored"
	finally:
		backend.user_delete(user_ids)


def test_user_deleteSelf(
	default_acl: dict,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	_create_agent(test_client, "test-delete-self-agent1")
	_create_agent(test_client, "test-delete-self-agent2")
	agent1 = ("test-delete-self-agent1", AGENT_PASSWORD)
	agent2 = ("test-delete-self-agent2", AGENT_PASSWORD)

	res = _rpc(test_client, "user_deleteSelf", agent1)
	assert "error" not in res
	# Only the calling agent is deleted
	assert [user.id for user in backend.user_getObjects(id=[agent1[0], agent2[0]])] == [agent2[0]]

	# The session is gone and the user can not authenticate anymore
	res = test_client.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "backend_getInterface", "params": []})
	assert res.status_code == 401
	test_client.reset_cookies()
	res = test_client.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "backend_getInterface", "params": []})
	assert res.status_code == 401

	# The last agent can be deleted
	test_client.reset_cookies()
	res = _rpc(test_client, "user_deleteSelf", agent2)
	assert "error" not in res
	assert not backend.user_getObjects(id=[agent1[0], agent2[0]])


def test_user_deleteSelf_user_already_deleted(
	default_acl: dict,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	_create_agent(test_client, "test-delete-self-agent1")
	agent = ("test-delete-self-agent1", AGENT_PASSWORD)
	test_client.auth = agent
	res = test_client.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "backend_getInterface", "params": []})
	assert res.status_code == 200

	# Deleted by an admin while the agent session is still valid
	backend.user_delete(agent[0])
	res = _rpc(test_client, "user_deleteSelf", agent)
	assert "error" not in res


def test_user_deleteSelf_denied_for_non_agent(
	user_delete_self_for_all: None,
	backend: UnprotectedBackend,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	backend.user_createObjects([User(id="test-delete-self-other")])
	res = _rpc(test_client, "user_deleteSelf", (ADMIN_USER, ADMIN_PASS))
	assert res["error"]["message"] == "Insufficient permissions"
	# Nothing was deleted
	assert backend.user_getObjects(id="test-delete-self-other")


def test_user_deleteSelf_audit(
	default_acl: dict,  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	_create_agent(test_client, "test-delete-self-agent1")
	with get_config({"audit_log_enabled": True}), test_client:
		res = _rpc(test_client, "user_deleteSelf", ("test-delete-self-agent1", AGENT_PASSWORD))
		assert "error" not in res

	audit_logs = _wait_for_logout_audit_logs(backend)
	assert len(audit_logs) == 1
	audit_log = audit_logs[0]
	assert audit_log.actorType == "agent"
	assert audit_log.username == "test-delete-self-agent1"
	assert audit_log.authentication
	assert audit_log.authentication.logoutReason == AuditLogAuthenticationLogoutReason.USER_REQUESTED


def test_user_deleteSelf_audit_denied(
	user_delete_self_for_all: None,
	backend: UnprotectedBackend,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	with get_config({"audit_log_enabled": True}), test_client:
		res = _rpc(test_client, "user_deleteSelf", (ADMIN_USER, ADMIN_PASS))
		assert "error" in res

	assert not _wait_for_logout_audit_logs(backend, timeout=2)
