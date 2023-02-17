# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
Test opsiconfd.dhcpd
"""

from pathlib import Path
from shutil import copy

from opsiconfd.dhcpd import DHCPDConfFile


def test_parse_dhcpd_conf(tmp_path: Path) -> None:
	dhcpd_conf = tmp_path / "dhcpd.conf"
	copy("tests/data/dhcpd/dhcpd.conf", dhcpd_conf)
	conf_file = DHCPDConfFile(dhcpd_conf)
	conf_file.parse()
	assert conf_file.get_host("opsi-test") == {"fixed-address": "opsi-test.domain.local", "hardware": "ethernet 9a:e5:3c:10:22:21"}
	assert conf_file.get_host("out-of-group") == {"fixed-address": "out-of-group.domain.local", "hardware": "ethernet 9a:e5:3c:10:22:22"}
	assert conf_file.get_host("out-of-subnet") == {"fixed-address": "out-of-subnet.domain.local", "hardware": "ethernet 1a:25:31:11:23:21"}

	group = conf_file.get_global_block().get_blocks("group", recursive=True)[0]
	assert group.get_parameters_hash() == {"next-server": "192.168.99.2", "filename": "linux/pxelinux.0/xxx?{}"}
	assert group.get_parameters_hash(inherit="global") == {
		"next-server": "192.168.99.2",
		"filename": "linux/pxelinux.0/xxx?{}",
		"ddns-update-style": "none",
		"default-lease-time": "68400",
		"max-lease-time": "68400",
		"authoritative": "",
		"log-facility": "local7",
		"use-host-decl-names": True,
	}


def test_add_host_to_dhcpd_conf(tmp_path: Path) -> None:
	dhcpd_conf = tmp_path / "dhcpd.conf"
	copy("tests/data/dhcpd/dhcpd.conf", dhcpd_conf)
	conf_file = DHCPDConfFile(dhcpd_conf)

	conf_file.add_host("TestclienT", "0001-21-21:00:00", "192.168.99.112", "192.168.99.112", None)
	conf_file.add_host(
		"TestclienT2",
		"00:01:09:08:99:11",
		"192.168.99.113",
		"192.168.99.113",
		{"next-server": "192.168.99.2", "filename": "linux/pxelinux.0/xxx?{}"},
	)

	assert conf_file.get_host("TestclienT") == {"fixed-address": "192.168.99.112", "hardware": "ethernet 00:01:21:21:00:00"}
	assert conf_file.get_host("TestclienT2") == {"fixed-address": "192.168.99.113", "hardware": "ethernet 00:01:09:08:99:11"}
	assert conf_file.get_host("notthere") is None

	conf_file.generate()

	conf_file = DHCPDConfFile(dhcpd_conf)
	conf_file.parse()
	assert conf_file.get_host("TestclienT") == {"fixed-address": "192.168.99.112", "hardware": "ethernet 00:01:21:21:00:00"}
	assert conf_file.get_host("TestclienT2") == {"fixed-address": "192.168.99.113", "hardware": "ethernet 00:01:09:08:99:11"}
	assert conf_file.get_host("notthere") is None
