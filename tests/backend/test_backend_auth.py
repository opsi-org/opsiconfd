# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.auth
"""

from pathlib import Path

import pytest
from opsi.exception import BackendPermissionDeniedError

from opsiconfd import contextvar_client_session
from opsiconfd.backend.auth import read_acl_file
from opsiconfd.backend.rpc.main import ProtectedBackend
from opsiconfd.session import OPSISession
from tests.utils import get_config


def test_read_acl_file(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	data = (
		"backend_deleteBase : sys_group(admingrp1,admingrp2)\n"
		"backend_.*         : all\n"
		"log_.*             : sys_user(admin1,admin2,attributes(attr1,attr2)); opsi_depotserver; self\n"
		"host_get.*         : sys_group(admingrp1,attributes(!attr1,!attr2)); opsi_depotserver; self;"
		"                     opsi_client(attributes(!opsiHostKey, !notes))\n"
		".*                 : sys_group(admingrp1); opsi_depotserver;;;;;;;;\n"  # Allow empty statement
	)
	acl_file.write_text(data=data, encoding="utf-8")
	protected_backend = ProtectedBackend()
	try:
		with get_config({"acl_file": str(acl_file)}):
			acl = read_acl_file(str(acl_file))
			assert len(acl) == 13

			assert acl[0].method_re.pattern == "backend_deleteBase"
			assert acl[0].type == "sys_group"
			assert acl[0].id == "admingrp1"
			assert not acl[0].allowed_attributes
			assert not acl[0].denied_attributes

			assert acl[1].method_re.pattern == "backend_deleteBase"
			assert acl[1].type == "sys_group"
			assert acl[1].id == "admingrp2"
			assert not acl[1].allowed_attributes
			assert not acl[1].denied_attributes

			assert acl[2].method_re.pattern == "backend_.*"
			assert acl[2].type == "all"
			assert not acl[2].id
			assert not acl[2].allowed_attributes
			assert not acl[2].denied_attributes

			assert acl[3].method_re.pattern == "log_.*"
			assert acl[3].type == "sys_user"
			assert acl[3].id == "admin1"
			assert acl[3].allowed_attributes == {"attr1", "attr2"}
			assert not acl[3].denied_attributes

			assert acl[4].method_re.pattern == "log_.*"
			assert acl[4].type == "sys_user"
			assert acl[4].id == "admin2"
			assert acl[4].allowed_attributes == {"attr1", "attr2"}
			assert not acl[4].denied_attributes

			assert acl[5].method_re.pattern == "log_.*"
			assert acl[5].type == "opsi_depotserver"
			assert not acl[5].id
			assert not acl[5].allowed_attributes
			assert not acl[5].denied_attributes

			assert acl[6].method_re.pattern == "log_.*"
			assert acl[6].type == "self"
			assert not acl[6].id
			assert not acl[6].allowed_attributes
			assert not acl[6].denied_attributes

			assert acl[7].method_re.pattern == "host_get.*"
			assert acl[7].type == "sys_group"
			assert acl[7].id == "admingrp1"
			assert not acl[7].allowed_attributes
			assert acl[7].denied_attributes == {"attr1", "attr2"}

			assert acl[8].method_re.pattern == "host_get.*"
			assert acl[8].type == "opsi_depotserver"
			assert not acl[8].id
			assert not acl[8].allowed_attributes
			assert not acl[8].denied_attributes

			assert acl[9].method_re.pattern == "host_get.*"
			assert acl[9].type == "self"
			assert not acl[9].id
			assert not acl[9].allowed_attributes
			assert not acl[9].denied_attributes

			assert acl[10].method_re.pattern == "host_get.*"
			assert acl[10].type == "opsi_client"
			assert not acl[10].id
			assert not acl[10].allowed_attributes
			assert acl[10].denied_attributes == {"opsiHostKey", "notes"}

			assert acl[11].method_re.pattern == ".*"
			assert acl[11].type == "sys_group"
			assert acl[11].id == "admingrp1"
			assert not acl[11].allowed_attributes
			assert not acl[11].denied_attributes

			assert acl[12].method_re.pattern == ".*"
			assert acl[12].type == "opsi_depotserver"
			assert not acl[12].id
			assert not acl[12].allowed_attributes
			assert not acl[12].denied_attributes

			protected_backend._read_acl_file()

			assert len(protected_backend._acl["backend_deleteBase"]) == 2
			assert protected_backend._acl["backend_deleteBase"][0].type == "sys_group"
			assert protected_backend._acl["backend_deleteBase"][0].id == "admingrp1"
			assert protected_backend._acl["backend_deleteBase"][1].type == "sys_group"
			assert protected_backend._acl["backend_deleteBase"][1].id == "admingrp2"

			for method in ("backend_createBase", "backend_getInterface", "backend_exit"):
				assert len(protected_backend._acl[method]) == 1
				assert protected_backend._acl[method][0].type == "all"

			for method in ("log_read", "log_write"):
				assert len(protected_backend._acl[method]) == 4
				assert protected_backend._acl[method][0].type == "sys_user"
				assert protected_backend._acl[method][0].id == "admin1"
				assert protected_backend._acl[method][0].allowed_attributes == {"attr1", "attr2"}
				assert protected_backend._acl[method][1].type == "sys_user"
				assert protected_backend._acl[method][1].id == "admin2"
				assert protected_backend._acl[method][1].allowed_attributes == {"attr1", "attr2"}
				assert protected_backend._acl[method][2].type == "opsi_depotserver"
				assert protected_backend._acl[method][3].type == "self"

			assert len(protected_backend._acl["host_getObjects"]) == 4
			assert protected_backend._acl["host_getObjects"][0].type == "sys_group"
			assert protected_backend._acl["host_getObjects"][0].id == "admingrp1"
			assert protected_backend._acl["host_getObjects"][0].denied_attributes == {"attr1", "attr2"}
			assert protected_backend._acl["host_getObjects"][1].type == "opsi_depotserver"
			assert protected_backend._acl["host_getObjects"][2].type == "self"
			assert protected_backend._acl["host_getObjects"][3].type == "opsi_client"
			assert protected_backend._acl["host_getObjects"][3].denied_attributes == {"opsiHostKey", "notes"}

			for method in (
				"host_createObjects",
				"host_updateObjects",
				"host_deleteObjects",
				"product_getObjects",
				"product_createObjects",
				"productOnDepot_updateObjects",
				"productOnClient_deleteObjects",
			):
				assert len(protected_backend._acl[method]) == 2
				assert protected_backend._acl[method][0].type == "sys_group"
				assert protected_backend._acl[method][0].id == "admingrp1"
				assert protected_backend._acl[method][1].type == "opsi_depotserver"

	finally:
		# Restore original ACL
		protected_backend._read_acl_file()


def test_read_acl_file_opsi_agent(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text(
		data=(
			"boot_getConfig : sys_group(admingrp1); opsi_depotserver; opsi_agent\n"
			"product_getObjects : opsi_agent(attributes(id,name))\n"
			"log_.*         : opsi_agent(agent1,agent2)\n"
		),
		encoding="utf-8",
	)
	acl = read_acl_file(acl_file)
	assert [(ace.method_re.pattern, ace.type, ace.id) for ace in acl] == [
		("boot_getConfig", "sys_group", "admingrp1"),
		("boot_getConfig", "opsi_depotserver", None),
		("boot_getConfig", "opsi_agent", None),
		("product_getObjects", "opsi_agent", None),
		("log_.*", "opsi_agent", "agent1"),
		("log_.*", "opsi_agent", "agent2"),
	]
	assert acl[3].allowed_attributes == {"id", "name"}
	assert not acl[3].denied_attributes


def test_get_ace_self_does_not_modify_shared_ace(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text(data="host_getObjects : self\n", encoding="utf-8")
	protected_backend = ProtectedBackend()
	contextvar_client_session_org = contextvar_client_session.get()
	try:
		with get_config({"acl_file": str(acl_file)}):
			protected_backend._read_acl_file()
			shared_ace = protected_backend._acl["host_getObjects"][0]
			assert shared_ace.type == "self"
			assert shared_ace.id is None

			for client_id in ("client1.opsi.test", "client2.opsi.test"):
				session = OPSISession("127.0.0.1")
				session.authenticated = True
				session.username = client_id
				session.host_id = client_id
				session.host_type = "OpsiClient"
				contextvar_client_session.set(session)

				ace_list = protected_backend._get_ace("host_getObjects")
				assert len(ace_list) == 1
				assert ace_list[0].type == "self"
				assert ace_list[0].id == client_id
				assert ace_list[0] is not shared_ace
				assert shared_ace.id is None
	finally:
		contextvar_client_session.set(contextvar_client_session_org)
		protected_backend._read_acl_file()


def _make_session(
	username: str,
	*,
	host_type: str | None = None,
	is_agent: bool = False,
	is_admin: bool = False,
	groups: set[str] | None = None,
) -> OPSISession:
	session = OPSISession("127.0.0.1")
	session.authenticated = True
	session.username = username
	if host_type:
		session.host_id = username
		session.host_type = host_type  # ty: ignore[invalid-assignment]
	session.is_agent = is_agent
	session.is_admin = is_admin
	session.user_groups = groups or set()
	return session


def test_get_ace_agent(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text(
		data=(
			"backend_.*      : all\n"
			"boot_getConfig  : sys_group(admingrp1); sys_user(user1); opsi_depotserver; opsi_client; self; opsi_agent\n"
			"log_write       : opsi_agent(agent2)\n"
			"host_getObjects : sys_group(admingrp1); opsi_depotserver; self; opsi_client\n"
		),
		encoding="utf-8",
	)
	protected_backend = ProtectedBackend()
	contextvar_client_session_org = contextvar_client_session.get()
	agent = _make_session("agent1", is_agent=True)
	try:
		with get_config({"acl_file": str(acl_file)}):
			protected_backend._read_acl_file()

			contextvar_client_session.set(agent)
			assert [ace.type for ace in protected_backend._get_ace("boot_getConfig")] == ["opsi_agent"]
			assert [ace.type for ace in protected_backend._get_ace("backend_getInterface")] == ["all"]
			# Entries of other types do not apply to agents
			with pytest.raises(BackendPermissionDeniedError):
				protected_backend._get_ace("host_getObjects")
			# Entries for another agent id do not apply
			with pytest.raises(BackendPermissionDeniedError):
				protected_backend._get_ace("log_write")

			contextvar_client_session.set(_make_session("agent2", is_agent=True))
			assert [(ace.type, ace.id) for ace in protected_backend._get_ace("log_write")] == [("opsi_agent", "agent2")]

			# opsi_agent entries do not apply to other session types
			for session, expected in (
				(_make_session("client1.opsi.test", host_type="OpsiClient"), ["opsi_client", "self"]),
				(_make_session("depot1.opsi.test", host_type="OpsiDepotserver"), ["opsi_depotserver", "self"]),
				(_make_session("user1"), ["sys_user"]),
				(_make_session("user2", is_admin=True, groups={"admingrp1"}), ["sys_group"]),
			):
				contextvar_client_session.set(session)
				assert [ace.type for ace in protected_backend._get_ace("boot_getConfig")] == expected
				with pytest.raises(BackendPermissionDeniedError):
					protected_backend._get_ace("log_write")
	finally:
		contextvar_client_session.set(contextvar_client_session_org)
		protected_backend._read_acl_file()


@pytest.mark.parametrize(
	"acl_path",
	(
		"opsiconfd_data/etc/backendManager/acl.conf",
		"docker/opsiconfd-dev/files/etc/opsi/backendManager/acl.conf",
		"tests/data/opsi-config/backendManager/acl.conf",
	),
)
def test_default_acl_agent(acl_path: str) -> None:
	protected_backend = ProtectedBackend()
	try:
		with get_config({"acl_file": acl_path}):
			protected_backend._read_acl_file()
			acl = protected_backend._acl

			assert {ace.type for ace in acl["boot_getConfig"]} == {"sys_group", "opsi_depotserver", "opsi_agent"}

			# Agents are not allowed to call anything else
			for method in (
				"host_getObjects",
				"host_getHashes",
				"host_getIdents",
				"config_getObjects",
				"productOnClient_getObjects",
				"user_getObjects",
				"host_updateObjects",
				"host_deleteObjects",
			):
				assert not [ace for ace in acl[method] if ace.type == "opsi_agent"], method
	finally:
		protected_backend._read_acl_file()


def test_check_role() -> None:
	protected_backend = ProtectedBackend()
	contextvar_client_session_org = contextvar_client_session.get()
	try:
		contextvar_client_session.set(_make_session("agent1", is_agent=True))
		protected_backend._check_role("agent")
		protected_backend._check_role("admin", "agent")
		with pytest.raises(BackendPermissionDeniedError):
			protected_backend._check_role("admin")

		contextvar_client_session.set(_make_session("admin1", is_admin=True, groups={"admingrp1"}))
		protected_backend._check_role("admin")
		protected_backend._check_role("admin", "agent")
		with pytest.raises(BackendPermissionDeniedError):
			protected_backend._check_role("agent")

		contextvar_client_session.set(_make_session("client1.opsi.test", host_type="OpsiClient"))
		with pytest.raises(BackendPermissionDeniedError):
			protected_backend._check_role("admin", "agent")

		for roles in (("unknown",), ("admin", "unknown")):
			with pytest.raises(ValueError, match="Invalid role 'unknown'"):
				protected_backend._check_role(*roles)

		contextvar_client_session.set(None)
		with pytest.raises(BackendPermissionDeniedError):
			protected_backend._check_role("admin")
	finally:
		contextvar_client_session.set(contextvar_client_session_org)


def test_acl_file_errors(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	for data in (
		"backend_deleteBase : sys_group(admingrp1\n",
		"backend_deleteBase : sys_grou(admin1)\n",
		"backend_deleteBase : sys_group\n",
		"backend_deleteBase : sys_user\n",
		"backend_deleteBase : sys_user((test)\n",
		"backend_deleteBase : sys_user(test))\n",
		"backend_deleteBase :\n",
	):
		acl_file.write_text(data=data, encoding="utf-8")
		with pytest.raises(ValueError, match=f".*at line 1 in acl file '{acl_file}'"):
			read_acl_file(acl_file)
