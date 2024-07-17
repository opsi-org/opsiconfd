# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
setup tests
"""

import os
import pwd
import shutil
from pathlib import Path
from unittest.mock import PropertyMock, patch

import pytest

from opsiconfd.setup.samba import get_smbd_service_name, is_samba3, setup_samba
from opsiconfd.config import opsi_config

EXPECTED_CONF = f"""
[opsi_depot]
   available = yes
   comment = opsi depot share (ro)
   path = /var/lib/opsi/depot
   follow symlinks = yes
   writeable = no
   invalid users = root
   acl allow execute always = true

[opsi_depot_rw]
   available = yes
   comment = opsi depot share (rw)
   path = /var/lib/opsi/depot
   follow symlinks = yes
   writeable = yes
   invalid users = root
   create mask = 0660
   directory mask = 0770
   acl allow execute always = true

[opsi_images]
   available = yes
   comment = opsi ntfs images share (rw)
   path = /var/lib/opsi/ntfs-images
   writeable = yes
   invalid users = root
   create mask = 0660
   directory mask = 0770

[opsi_workbench]
   available = yes
   comment = opsi workbench
   path = /var/lib/opsi/workbench
   writeable = yes
   invalid users = root {opsi_config.get('depot_user', 'username')}
   create mask = 0660
   directory mask = 0770
   acl allow execute always = true

[opsi_repository]
   available = yes
   comment = opsi repository share (ro)
   path = /var/lib/opsi/repository
   follow symlinks = yes
   writeable = no
   invalid users = root {opsi_config.get('depot_user', 'username')}

[opsi_logs]
   available = yes
   comment = opsi logs share (ro)
   path = /var/log/opsi
   follow symlinks = yes
   writeable = no
   invalid users = root {opsi_config.get('depot_user', 'username')}
"""


@pytest.mark.parametrize(
	"version_string, samba3",
	(
		("Version 3.1.1", True),
		("Version 4.15.13-Ubuntu", False),
	),
)
def test_setup_samba_add(tmp_path: Path, version_string: str, samba3: bool) -> None:
	is_samba3.cache_clear()

	smb_conf = tmp_path / "smb.conf"
	shutil.copy("tests/data/samba/smb.conf", smb_conf)

	class Proc:
		stdout = version_string

	with (
		patch("opsiconfd.setup.samba.run", PropertyMock(return_value=Proc())),
		patch("opsiconfd.setup.samba.SMB_CONF", str(smb_conf)),
		patch("opsiconfd.utils.user.pwd.getpwnam", lambda x: pwd.getpwuid(os.getuid())),
	):
		assert is_samba3() == samba3
		setup_samba()

	data = smb_conf.read_text(encoding="utf-8")

	expected_conf = EXPECTED_CONF
	if samba3:
		expected_conf = expected_conf.replace("   acl allow execute always = true\n", "")
	assert expected_conf in data


def test_setup_samba_keep_settings(tmp_path: Path) -> None:
	is_samba3.cache_clear()

	smb_conf = tmp_path / "smb.conf"
	shutil.copy("tests/data/samba/smb.conf", smb_conf)
	depot_share = (
		"[opsi_depot]\n"
		"  available = yes\n"
		"  directory mask = 0777\n"
		"  comment = opsi depot share (ro)\n"
		"  path = /var/lib/opsi/depot\n"
		"  follow symlinks = no\n"
		"  writeable = no\n"
		"  invalid users = root\n"
	)
	data = smb_conf.read_text(encoding="utf-8")
	smb_conf.write_text(data + "\n" + depot_share, encoding="utf-8")

	with patch("opsiconfd.setup.samba.SMB_CONF", str(smb_conf)):
		setup_samba()
	data = smb_conf.read_text(encoding="utf-8")
	assert depot_share + "   acl allow execute always = true\n\n" in data


LIST_UNITS_OUT = """
UNIT FILE                                  STATE           VENDOR PRESET
proc-sys-fs-binfmt_misc.automount          static          -
-.mount                                    generated       -
boot-efi.mount                             generated       -
boot.mount                                 generated       -
bolt.service                               static          -
{{service_name}}.service                       enabled         enabled
cloud-config.service                       enabled         enabled
cloud-final.service                        enabled         enabled

"""


@pytest.mark.parametrize(
	"out_name, service_name",
	(
		("smbd", "smbd"),
		("samba@", "samba"),
		("samba", "samba"),
		("smb", "smb"),
		("other", "smbd"),
	),
)
def test_get_smbd_service_name(out_name: str, service_name: str) -> None:
	get_smbd_service_name.cache_clear()
	out = LIST_UNITS_OUT.replace("{{service_name}}", out_name)

	class Proc:
		stdout = out

	with patch("opsiconfd.setup.samba.run", PropertyMock(return_value=Proc())):
		assert get_smbd_service_name() == service_name
