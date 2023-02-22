# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
setup tests
"""

import os
import pwd
import shutil
from pathlib import Path
from time import sleep
from unittest.mock import PropertyMock, patch

import pytest

from opsiconfd.dhcpd import DHCPDControlConfig
from opsiconfd.setup.sudo import format_command, setup_sudoers

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


@pytest.mark.parametrize("conf_file", ("sudoers1", "sudoers2"))
def test_setup_sudoers(conf_file: str, tmp_path: Path) -> None:
	sudoers = tmp_path / "sudoers"
	shutil.copy(f"tests/data/sudo/{conf_file}", sudoers)
	dhcpd_config = DHCPDControlConfig(
		enabled=True,
		dhcpd_on_depot=False,
		dhcpd_config_file=None,  # type: ignore[arg-type]
		reload_config_command=["/sbin/systemctl", "reload", "dhcpd"],
		fixed_address_format="FQDN",
		default_client_parameters={},
	)
	with (
		patch("opsiconfd.setup.sudo.SUDOERS_CONF", str(sudoers)),
		patch("opsiconfd.setup.sudo.get_dhcpd_control_config", lambda: dhcpd_config),
	):
		includedir = ""
		for line in sudoers.read_text(encoding="utf-8").splitlines(keepends=True):
			if "includedir" in line:
				includedir = line

		mtime = sudoers.stat().st_mtime
		sleep(0.1)
		setup_sudoers()
		data = sudoers.read_text(encoding="utf-8")

		assert data.endswith(
			"# Auto added by opsiconfd setup\n"
			"Defaults:opsiconfd !requiretty\n"
			"opsiconfd ALL=NOPASSWD: /usr/bin/opsi-set-rights\n"
			"opsiconfd ALL=NOPASSWD: /sbin/systemctl reload dhcpd\n"
			"\n"
			f"{includedir}"
		)
		assert sudoers.stat().st_mtime != mtime
		mtime = sudoers.stat().st_mtime

		# File should stay unmodified
		sleep(0.1)
		setup_sudoers()
		data2 = sudoers.read_text(encoding="utf-8")
		assert data == data2
		assert sudoers.stat().st_mtime == mtime

		dhcpd_config.enabled = False
		sleep(0.1)
		setup_sudoers()
		data = sudoers.read_text(encoding="utf-8")
		assert data.endswith(
			"# Auto added by opsiconfd setup\n"
			"Defaults:opsiconfd !requiretty\n"
			"opsiconfd ALL=NOPASSWD: /usr/bin/opsi-set-rights\n"
			"\n"
			f"{includedir}"
		)
		assert sudoers.stat().st_mtime != mtime

		sudoers.write_text(includedir, encoding="utf-8")
		setup_sudoers()
		data = sudoers.read_text(encoding="utf-8")
		assert data == (
			"# Auto added by opsiconfd setup\n"
			"Defaults:opsiconfd !requiretty\n"
			"opsiconfd ALL=NOPASSWD: /usr/bin/opsi-set-rights\n"
			"\n"
			f"{includedir}"
		)

		sudoers.write_text("", encoding="utf-8")
		setup_sudoers()
		data = sudoers.read_text(encoding="utf-8")
		assert data == (
			"# Auto added by opsiconfd setup\nDefaults:opsiconfd !requiretty\nopsiconfd ALL=NOPASSWD: /usr/bin/opsi-set-rights\n\n"
		)
		mtime = sudoers.stat().st_mtime

		sleep(0.1)
		setup_sudoers()
		assert sudoers.stat().st_mtime == mtime
