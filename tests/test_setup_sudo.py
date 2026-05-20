# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
setup tests
"""

import shutil
from pathlib import Path
from time import sleep
from unittest.mock import patch

import pytest

from opsiconfd.dhcpd import DHCPDControlConfig
from opsiconfd.setup.sudo import format_command, setup_sudoers

from .utils import get_config

SYSTEMCTL = shutil.which("systemctl") or "/usr/bin/systemctl"


@pytest.mark.parametrize(
	"cmd, expected",
	(
		(["sudo", "systemctl", "restart", "dhcpd"], f"{SYSTEMCTL} restart dhcpd"),
		("sudo /usr/local/bin/systemctl restart dhcpd", "/usr/local/bin/systemctl restart dhcpd"),
		("/usr/bin/sudo systemctl restart dhcpd", f"{SYSTEMCTL} restart dhcpd"),
		("systemctl  restart   isc-dhcpd  ", f"{SYSTEMCTL} restart isc-dhcpd"),
	),
)
def test_format_command(cmd: list[str] | str, expected: str) -> None:
	assert format_command(cmd) == expected


@pytest.mark.parametrize(
	"set_rights_file_admin_group,set_rights_opsiconfd,opsiconfd_setup_admin_group,opsiconfd_dhcpd_reload,dhcpd_config_enabled",
	(
		(False, False, False, False, False),
		(False, True, False, False, False),
		(True, True, True, True, True),
		(True, True, True, False, True),
		(True, True, True, True, False),
	),
)
def test_setup_sudoers(
	tmp_path: Path,
	set_rights_file_admin_group: bool,
	set_rights_opsiconfd: bool,
	opsiconfd_setup_admin_group: bool,
	opsiconfd_dhcpd_reload: bool,
	dhcpd_config_enabled: bool,
) -> None:

	sudoers = tmp_path / "sudoers"
	shutil.copy("tests/data/sudo/sudoers", sudoers)
	dhcpd_config = DHCPDControlConfig(
		enabled=dhcpd_config_enabled,
		dhcpd_on_depot=False,
		dhcpd_config_file=None,  # ty: ignore[invalid-argument-type]
		reload_config_command=["/sbin/systemctl", "reload", "dhcpd"],
		fixed_address_format="FQDN",
		default_client_parameters={},
		boot_filename_uefi="",
		boot_filename_bios="",
	)
	setup_sudo_entries = []
	if set_rights_file_admin_group:
		setup_sudo_entries.append("set_rights_file_admin_group")
	if set_rights_opsiconfd:
		setup_sudo_entries.append("set_rights_opsiconfd")
	if opsiconfd_setup_admin_group:
		setup_sudo_entries.append("opsiconfd_setup_admin_group")
	if opsiconfd_dhcpd_reload:
		setup_sudo_entries.append("opsiconfd_dhcpd_reload")

	with (
		patch("opsiconfd.setup.sudo.SUDOERS_CONF", str(sudoers)),
		patch("opsiconfd.setup.sudo.get_dhcpd_control_config", lambda: dhcpd_config),
		get_config({"setup_sudo_entries": setup_sudo_entries}),
	):
		mtime = sudoers.stat().st_mtime
		sleep(0.1)
		setup_sudoers()

		expected_lines = [
			"# Auto added by opsiconfd setup",
			"Defaults:opsiconfd !requiretty",
		]
		if set_rights_opsiconfd:
			expected_lines.append("opsiconfd ALL=NOPASSWD: /usr/bin/opsi-set-rights")
		if set_rights_file_admin_group:
			expected_lines.append("%opsifileadmins ALL=NOPASSWD: /usr/bin/opsi-set-rights")
		if opsiconfd_setup_admin_group:
			expected_lines.append("%opsiadmin ALL=NOPASSWD: /usr/bin/opsiconfd setup *")
		if dhcpd_config_enabled and opsiconfd_dhcpd_reload:
			expected_lines.append("opsiconfd ALL=NOPASSWD: /sbin/systemctl reload dhcpd")
		expected = "\n".join(expected_lines) + "\n\n"

		data = sudoers.read_text(encoding="utf-8")
		assert data.endswith(expected)
		assert sudoers.stat().st_mtime != mtime
		mtime = sudoers.stat().st_mtime

		# File should stay unmodified because the content is already correct
		sleep(1)
		setup_sudoers()
		data2 = sudoers.read_text(encoding="utf-8")
		assert data == data2
		assert sudoers.stat().st_mtime == mtime

		# Test removal
		sleep(1)
		with get_config({"setup_sudo_entries": []}):
			setup_sudoers()

			expected_lines = [
				"# Auto added by opsiconfd setup",
				"Defaults:opsiconfd !requiretty",
			]
			expected = "\n".join(expected_lines) + "\n\n"
			data = sudoers.read_text(encoding="utf-8")
			assert data.endswith(expected)
			if (
				set_rights_opsiconfd
				or set_rights_file_admin_group
				or opsiconfd_setup_admin_group
				or (dhcpd_config_enabled and opsiconfd_dhcpd_reload)
			):
				assert sudoers.stat().st_mtime != mtime
