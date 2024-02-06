# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.auth
"""

from pathlib import Path

import pytest

from opsiconfd.backend.auth import read_acl_file


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
