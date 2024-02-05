# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
setup tests
"""

import os
import resource
from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from unittest.mock import patch

from opsiconfd.setup import cleanup_log_files, setup_file_permissions, setup_limits, setup_systemd
from opsiconfd.setup import setup as opsiconfd_setup
from opsiconfd.setup.files import migrate_acl_conf_if_default

from .utils import ACL_CONF_41, get_config


def test_setup_limits() -> None:
	(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
	soft_limit = 1000
	resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, max(hard_limit, soft_limit)))
	setup_limits()
	(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
	assert soft_limit == 10000


def test_setup_file_permissions() -> None:
	with (
		patch("opsicommon.server.rights.FilePermission.chmod") as mock_file_chmod,
		patch("opsicommon.server.rights.FilePermission.chown") as mock_file_chown,
		patch("opsicommon.server.rights.DirPermission.chmod"),
		patch("opsicommon.server.rights.DirPermission.chown"),
	):
		setup_file_permissions()
		mock_file_chmod.assert_called()
		mock_file_chown.assert_called()


def test_setup_systemd() -> None:
	with patch("subprocess.check_output"):
		setup_systemd()


def test_cleanup_log_files(tmp_path: Path) -> None:
	invalid_link = tmp_path / "invalid_link.log"
	log_file = tmp_path / "opsiconfd.log"
	log_file_old = tmp_path / "opsiconfd.1.log"
	os.symlink(str(tmp_path / "notexisting"), str(invalid_link))
	log_file.write_text("")
	log_file_old.write_text("")
	os.utime(str(log_file_old), (0, 0))
	files = os.listdir(str(tmp_path))
	with get_config({"log_file": str(log_file)}):
		cleanup_log_files()
	files = os.listdir(str(tmp_path))
	assert files == [log_file.name]


@contextmanager
def mock_all() -> Generator[dict, None, None]:
	with (
		patch("opsiconfd.setup.setup_limits") as mock_setup_limits,
		patch("opsiconfd.setup.setup_backend") as mock_setup_backend,
		patch("opsiconfd.setup.po_setup_users_and_groups") as mock_po_setup_users_and_groups,
		patch("opsiconfd.setup.setup_users_and_groups") as mock_setup_users_and_groups,
		patch("opsiconfd.setup.setup_files") as mock_setup_files,
		patch("opsiconfd.setup.setup_systemd") as mock_setup_systemd,
		patch("opsiconfd.setup.setup_file_permissions") as mock_setup_file_permissions,
		patch("opsiconfd.setup.cleanup_log_files") as mock_cleanup_log_files,
		patch("opsiconfd.setup.setup_grafana") as mock_setup_grafana,
		patch("opsiconfd.setup.setup_metric_downsampling") as mock_setup_metric_downsampling,
		patch("opsiconfd.setup.setup_ssl") as mock_setup_ssl,
		patch("opsiconfd.setup.setup_samba") as mock_setup_samba,
		patch("opsiconfd.setup.setup_dhcpd") as mock_setup_dhcpd,
		patch("opsiconfd.setup.setup_sudoers") as mock_setup_sudoers,
	):
		yield {
			"setup_limits": mock_setup_limits,
			"setup_backend": mock_setup_backend,
			"po_setup_users_and_groups": mock_po_setup_users_and_groups,
			"setup_users_and_groups": mock_setup_users_and_groups,
			"setup_files": mock_setup_files,
			"setup_systemd": mock_setup_systemd,
			"setup_file_permissions": mock_setup_file_permissions,
			"cleanup_log_files": mock_cleanup_log_files,
			"setup_grafana": mock_setup_grafana,
			"setup_metric_downsampling": mock_setup_metric_downsampling,
			"setup_ssl": mock_setup_ssl,
			"setup_samba": mock_setup_samba,
			"setup_dhcpd": mock_setup_dhcpd,
			"setup_sudoers": mock_setup_sudoers,
		}


def test_setup_skip_all() -> None:
	with mock_all() as funcs:
		with get_config({"skip_setup": ["all"]}) as config:
			opsiconfd_setup()
			assert config.skip_setup == [
				"all",
				"limits",
				"users",
				"groups",
				"grafana",
				"backend",
				"ssl",
				"server_cert",
				"opsi_ca",
				"systemd",
				"files",
				"file_permissions",
				"log_files",
				"metric_downsampling",
				"samba",
				"dhcpd",
				"sudoers",
			]
			for mock in funcs.values():
				mock.assert_not_called()


def test_setup_skip_ssl() -> None:
	with get_config({"skip_setup": ["ssl", "log_files"]}) as config:
		assert config.skip_setup == ["ssl", "log_files", "opsi_ca", "server_cert"]


def test_setup_skip_users_and_files() -> None:
	with mock_all() as funcs:
		with get_config({"skip_setup": ["users", "files"]}):
			opsiconfd_setup(explicit=True)
			funcs["po_setup_users_and_groups"].assert_not_called()
			funcs["setup_users_and_groups"].assert_not_called()
			funcs["setup_files"].assert_not_called()
			funcs["setup_ssl"].assert_called()


def test_setup_explicit() -> None:
	with mock_all() as funcs:
		opsiconfd_setup(explicit=False)
		funcs["setup_systemd"].assert_not_called()
	with mock_all() as funcs:
		opsiconfd_setup(explicit=True)
		funcs["setup_systemd"].assert_called()


def test_migrate_acl_conf_if_default(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text(ACL_CONF_41, encoding="utf-8")
	acl_conf_43 = Path("opsiconfd_data/etc/backendManager/acl.conf").read_text(encoding="utf-8")
	with get_config({"acl_file": str(acl_file)}):
		migrate_acl_conf_if_default()
	assert acl_file.read_text(encoding="utf-8") == acl_conf_43
