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
from unittest.mock import patch

from opsiconfd.dhcpd import (
	DHCPDConfFile,
	DHCPDConfParameter,
	DHCPDControlConfig,
	setup_dhcpd,
)


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


def test_setup_dhcpd(tmp_path: Path) -> None:
	dhcpd_conf = tmp_path / "dhcpd.conf"
	copy("tests/data/dhcpd/dhcpd2.conf", dhcpd_conf)

	dhcpd_config = DHCPDControlConfig(
		enabled=True,
		dhcpd_on_depot=False,
		dhcpd_config_file=DHCPDConfFile(dhcpd_conf),
		reload_config_command=[],
		fixed_address_format="IP",
		default_client_parameters={},
		boot_filename_uefi="opsi/opsi-linux-bootimage/loader/opsi-netboot.efi",
		boot_filename_bios="opsi/opsi-linux-bootimage/loader/opsi-netboot.bios",
	)
	with patch("opsiconfd.dhcpd.get_dhcpd_control_config", lambda: dhcpd_config):
		setup_dhcpd()
		dhcpd_config.dhcpd_config_file.parse()

		param = dhcpd_config.dhcpd_config_file.get_global_block().get_blocks(type="if", recursive=True)[0].components[1]
		assert isinstance(param, DHCPDConfParameter)
		assert param.key == "filename"
		assert param.value == dhcpd_config.boot_filename_bios

		param = dhcpd_config.dhcpd_config_file.get_global_block().get_blocks(type="else", recursive=True)[0].components[1]
		assert isinstance(param, DHCPDConfParameter)
		assert param.key == "filename"
		assert param.value == dhcpd_config.boot_filename_uefi

		# Empty conf
		dhcpd_conf.write_text("", encoding="utf-8")
		setup_dhcpd()

		dhcpd_config.dhcpd_config_file.parse()

		param = dhcpd_config.dhcpd_config_file.get_global_block().get_blocks(type="if", recursive=True)[0].components[0]
		assert isinstance(param, DHCPDConfParameter)
		assert param.key == "filename"
		assert param.value == dhcpd_config.boot_filename_bios

		param = dhcpd_config.dhcpd_config_file.get_global_block().get_blocks(type="else", recursive=True)[0].components[0]
		assert isinstance(param, DHCPDConfParameter)
		assert param.key == "filename"
		assert param.value == dhcpd_config.boot_filename_uefi
