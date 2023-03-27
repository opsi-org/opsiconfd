# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.general
"""

import os
import pwd
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from opsicommon.license import OPSI_CLIENT_INACTIVE_AFTER
from opsicommon.objects import LocalbootProduct, OpsiClient, ProductOnClient

from opsiconfd.utils import blowfish_encrypt
from tests.utils import (  # pylint: disable=unused-import
	UnprotectedBackend,
	backend,
	clean_mysql,
)


@pytest.mark.parametrize(
	"last_seen_days, macos, linux, windows",
	[
		(OPSI_CLIENT_INACTIVE_AFTER - 1000, 1, 2, 6),
		(OPSI_CLIENT_INACTIVE_AFTER - 1, 1, 2, 6),
		(OPSI_CLIENT_INACTIVE_AFTER, 1, 1, 4),
		(OPSI_CLIENT_INACTIVE_AFTER + 1, 1, 1, 4),
		(OPSI_CLIENT_INACTIVE_AFTER + 1000, 1, 1, 4),
	],
)
def test_get_client_info(  # pylint: disable=too-many-locals
	backend: UnprotectedBackend, last_seen_days: int, macos: int, linux: int, windows: int  # pylint: disable=redefined-outer-name
) -> None:
	hosts = backend.host_getIdents(type="OpsiClient")
	assert len(hosts) == 0

	now = datetime.now()
	now_str = now.strftime("%Y-%m-%d %H:%M:%S")
	last_seen = now - timedelta(days=last_seen_days)
	last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M:%S")

	client1 = OpsiClient(id="test-backend-rpc-general-1.opsi.org", lastSeen=now_str)
	client2 = OpsiClient(id="test-backend-rpc-general-2.opsi.org", lastSeen=now_str)
	client3 = OpsiClient(id="test-backend-rpc-general-3.opsi.org", lastSeen=last_seen_str)
	client4 = OpsiClient(id="test-backend-rpc-general-4.opsi.org", lastSeen=now_str)
	client5 = OpsiClient(id="test-backend-rpc-general-5.opsi.org", lastSeen=now_str)
	client6 = OpsiClient(id="test-backend-rpc-general-6.opsi.org", lastSeen=last_seen_str)
	client7 = OpsiClient(id="test-backend-rpc-general-7.opsi.org", lastSeen=now_str)
	client8 = OpsiClient(id="test-backend-rpc-general-8.opsi.org", lastSeen=now_str)
	client9 = OpsiClient(id="test-backend-rpc-general-9.opsi.org", lastSeen=last_seen_str)

	oca = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.0.0", packageVersion="1")
	olca = LocalbootProduct(id="opsi-linux-client-agent", productVersion="4.3.0.0", packageVersion="1")
	omca = LocalbootProduct(id="opsi-mac-client-agent", productVersion="4.3.0.0", packageVersion="1")

	pocs = [
		ProductOnClient(
			productId=oca.id,
			productType=oca.getType(),
			clientId=client1.id,
			productVersion=oca.productVersion,
			packageVersion=oca.packageVersion,
			installationStatus="installed",
		),
		ProductOnClient(
			productId=oca.id,
			productType=oca.getType(),
			clientId=client2.id,
			productVersion=oca.productVersion,
			packageVersion=oca.packageVersion,
			installationStatus="not_installed",
		),
		ProductOnClient(
			productId=oca.id,
			productType=oca.getType(),
			clientId=client3.id,
			productVersion=oca.productVersion,
			packageVersion=oca.packageVersion,
			installationStatus="installed",
		),
		ProductOnClient(
			productId=olca.id,
			productType=olca.getType(),
			clientId=client4.id,
			productVersion=olca.productVersion,
			packageVersion=olca.packageVersion,
			installationStatus="installed",
		),
		ProductOnClient(
			productId=olca.id,
			productType=olca.getType(),
			clientId=client5.id,
			productVersion=olca.productVersion,
			packageVersion=olca.packageVersion,
			installationStatus="not_installed",
		),
		ProductOnClient(
			productId=olca.id,
			productType=olca.getType(),
			clientId=client6.id,
			productVersion=olca.productVersion,
			packageVersion=olca.packageVersion,
			installationStatus="installed",
		),
		ProductOnClient(
			productId=omca.id,
			productType=omca.getType(),
			clientId=client1.id,
			productVersion=omca.productVersion,
			packageVersion=omca.packageVersion,
			installationStatus="installed",
		),
	]

	backend.host_createObjects([client1, client2, client3, client4, client5, client6, client7, client8, client9])
	backend.product_createObjects([oca, olca, omca])
	backend.productOnClient_createObjects(pocs)

	info = backend._get_client_info()  # type: ignore[misc] # pylint: disable=protected-access
	print(info)
	assert info["macos"] == macos
	assert info["linux"] == linux
	assert info["windows"] == windows


def test_user_setCredentials(backend: UnprotectedBackend, tmp_path: Path) -> None:  # pylint: disable=invalid-name,redefined-outer-name
	class Proc:  # pylint: disable=too-few-public-methods
		test_input: dict[str, dict[str, Any]] = {}
		test_output: dict[str, str | Exception] = {}
		stdout: str = ""

	proc = Proc()

	def run(cmd: list[str], **kwargs: Any) -> Proc:
		cmd_str = " ".join(cmd)
		proc.test_input[cmd_str] = kwargs
		out = proc.test_output.get(cmd_str, "")
		proc.stdout = str(out)
		if isinstance(out, Exception):
			raise out
		return proc

	opsi_passwd_file = tmp_path / "passwd"
	with (
		patch("opsiconfd.backend.rpc.obj_user.OPSI_PASSWD_FILE", opsi_passwd_file),
		patch("opsiconfd.backend.rpc.obj_user.is_local_user", lambda x: True),
		patch("opsiconfd.backend.rpc.obj_user.run", run),
		patch("opsiconfd.backend.rpc.obj_user.pwd.getpwnam", lambda x: pwd.getpwuid(os.getuid())),
	):
		proc.test_output["ucr get server/role"] = FileNotFoundError()
		backend.user_setCredentials("pcpatch", "password")
		enc_password = blowfish_encrypt(backend.host_getObjects(type="OpsiConfigserver")[0].opsiHostKey, "password")
		assert opsi_passwd_file.read_text(encoding="utf-8") == f"pcpatch:{enc_password}\n"
		cmds = list(proc.test_input)
		assert cmds == ["ucr get server/role", "smbldap-passwd pcpatch"]

		proc.test_input = {}
		proc.test_output["ucr get server/role"] = FileNotFoundError()
		proc.test_output["smbldap-passwd pcpatch"] = FileNotFoundError()
		backend.user_setCredentials("pcpatch", "password")
		enc_password = blowfish_encrypt(backend.host_getObjects(type="OpsiConfigserver")[0].opsiHostKey, "password")
		assert opsi_passwd_file.read_text(encoding="utf-8") == f"pcpatch:{enc_password}\n"
		cmds = list(proc.test_input)
		assert cmds == ["ucr get server/role", "smbldap-passwd pcpatch", "chpasswd", "smbpasswd -a -s pcpatch"]

		proc.test_input = {}
		proc.test_output["ucr get server/role"] = "some_ucs_role"
		backend.user_setCredentials("pcpatch", "password")
		cmds = list(proc.test_input)
		assert cmds == ["ucr get server/role"]

		proc.test_input = {}
		proc.test_output["ucr get server/role"] = "domaincontroller_master"
		proc.test_output["univention-admin users/user list --filter (uid=pcpatch)"] = "DN: cn=pcpatch,dc=x,dc=y"
		backend.user_setCredentials("pcpatch", "password")
		cmds = list(proc.test_input)
		assert cmds == [
			"ucr get server/role",
			"univention-admin users/user list --filter (uid=pcpatch)",
			"univention-admin users/user modify --dn cn=pcpatch,dc=x,dc=y"
			" --set password='password' --set overridePWLength=1 --set overridePWHistory=1",
		]

		proc.test_input = {}
		backend.user_setCredentials("pcpatch2", "password2")
		enc_password2 = blowfish_encrypt(backend.host_getObjects(type="OpsiConfigserver")[0].opsiHostKey, "password2")
		assert opsi_passwd_file.read_text(encoding="utf-8") == f"pcpatch:{enc_password}\npcpatch2:{enc_password2}\n"
		assert not proc.test_input

		backend.user_setCredentials("pcpatch", "password3")
		enc_password3 = blowfish_encrypt(backend.host_getObjects(type="OpsiConfigserver")[0].opsiHostKey, "password3")
		assert opsi_passwd_file.read_text(encoding="utf-8") == f"pcpatch:{enc_password3}\npcpatch2:{enc_password2}\n"

		assert backend.user_getCredentials("pcpatch") == {"password": "password3", "rsaPrivateKey": ""}
