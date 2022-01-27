# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
config tests
"""

import os
import re
from argparse import ArgumentTypeError
from unittest.mock import patch

import pytest

from opsiconfd.config import network_address, ip_address, str2bool

from .utils import get_config


@pytest.mark.parametrize("value, expexted_value, exception", [
	("10.10.0.0/16", "10.10.0.0/16", None),
	("10.10.0.0/255.255.255.0", "10.10.0.0/24", None),
	("10.10.10.10/16", None, ArgumentTypeError),
	("10.10.10.10", "10.10.10.10/32", None),
	("fe80:0000::/10", "fe80::/10", None),
	("2001:0db8:1234:0000:0000:0000:0000:0000/48", "2001:db8:1234::/48", None)
])
def test_network_address(value, expexted_value, exception):
	if exception:
		with pytest.raises(exception):
			network_address(value)
	else:
		assert network_address(value) == expexted_value


@pytest.mark.parametrize("value, expexted_value, exception", [
	("10.10.0.1", "10.10.0.1", None),
	("10.10.0.1/32", None, ArgumentTypeError),
	("2001:0db8:1234:0000:0000:0000:0000:0001", "2001:db8:1234::1", None),
	("::1", "::1", None),
	("127.0.0.1", "127.0.0.1", None)
])
def test_ip_address(value, expexted_value, exception):
	if exception:
		with pytest.raises(exception):
			ip_address(value)
	else:
		assert ip_address(value) == expexted_value


@pytest.mark.parametrize("value, expexted_value", [
	("yes", True),
	("y", True),
	("true", True),
	("1", True),
	(True, True),
	("0", False),
	("no", False),
	("false", False),
	(False, False)
])
def test_str2bool(value, expexted_value):
	assert str2bool(value) is expexted_value


@pytest.mark.parametrize("arguments, config_name, expexted_value", [
	(["--backend-config-dir", "/test"], "backend_config_dir", "/test"),
	(["--dispatch-config-file", "/filename"], "dispatch_config_file", "/filename"),
	(["--extension-config-dir", "/test"], "extension_config_dir", "/test"),
	(["--admin-networks", "10.10.10.0/24", "10.10.20.0/24"], "admin_networks", ["10.10.10.0/24", "10.10.20.0/24"]),
	(["--symlink-logs"], "symlink_logs", True),
])
def test_cmdline(arguments, config_name, expexted_value):
	config = get_config(arguments)
	assert getattr(config, config_name) == expexted_value


@pytest.mark.parametrize("varname, value, config_name, expexted_value", [
	("OPSICONFD_BACKEND_CONFIG_DIR", "/test", "backend_config_dir", "/test"),
	("OPSICONFD_DISPATCH_CONFIG_FILE", "/filename", "dispatch_config_file", "/filename"),
	("OPSICONFD_EXTENSION_CONFIG_DIR", "/test", "extension_config_dir", "/test"),
	("OPSICONFD_ADMIN_NETWORKS", "[10.10.10.0/24,10.10.20.0/24]", "admin_networks", ["10.10.10.0/24", "10.10.20.0/24"]),
	("OPSICONFD_SYMLINK_LOGS", "yes", "symlink_logs", True),
	("OPSICONFD_SSL_CA_KEY_PASSPHRASE", "", "ssl_ca_key_passphrase", None),
	("OPSICONFD_SSL_SERVER_KEY_PASSPHRASE", "", "ssl_server_key_passphrase", None),
])
def test_environment_vars(varname, value, config_name, expexted_value):
	os.environ[varname] = value
	config = get_config([])
	try:
		assert getattr(config, config_name) == expexted_value
	finally:
		del os.environ[varname]


@pytest.mark.parametrize("varname, value, config_name, expexted_value", [
	("backend-config-dir", "/test", "backend_config_dir", "/test"),
	("dispatch-config-file", "/filename", "dispatch_config_file", "/filename"),
	("extension-config-dir", "/test", "extension_config_dir", "/test"),
	("admin-networks", "[10.10.10.0/24,10.10.20.0/24]", "admin_networks", ["10.10.10.0/24", "10.10.20.0/24"]),
	("symlink-logs", "1", "symlink_logs", True),
	("symlink-logs", "false", "symlink_logs", False),
	("symlink-logs", "no", "symlink_logs", False),
])
def test_config_file(tmp_path, varname, value, config_name, expexted_value):
	conf_file = tmp_path / "opsiconfd.conf"
	conf_file.write_text(f"{varname} = {value}")
	config = get_config(["--config", str(conf_file)])
	assert getattr(config, config_name) == expexted_value


def test_help():
	text = ""

	def print_message(self, message, file=None):  # pylint: disable=unused-argument
		nonlocal text
		text = message

	with (
		patch("argparse.ArgumentParser._print_message", print_message),
		patch("sys.stdout.isatty", lambda: True)
	):
		config = get_config(["--help"])  # pylint: disable=protected-access
		with pytest.raises(SystemExit):
			config._parse_args()  # pylint: disable=protected-access
		assert "Set maximum log message length" not in text

		text = ""
		config = get_config(["--ex-help"])  # pylint: disable=protected-access
		with pytest.raises(SystemExit):
			config._parse_args()  # pylint: disable=protected-access
		assert "Set maximum log message length" in text


def test_upgrade_config_files(tmp_path):
	config_file = tmp_path / "opsiconfd.conf"
	config_file.write_text((
		"[global]\n"
		"backend config dir = /backend/config/dir\n"
		"; backend config dir = comment1\n"
		"# backend config dir = comment2\n"
		"dispatch config file = /dispatch/config/file\n"
		"extension config dir = /extension/config/dir\n"
		"acl file = /acl/file\n"
		"admin networks = 10.10.0.0/16\n"
		"pid file = /var/run/opsiconfd/opsiconfd.pid\n"
		"log file = /log/file\n"
		"symlink logs = no\n"
		"log level = 1\n"
		"log format = [%l] [%D] %M (%F|%N)\n"
		"max log size = 5MB\n"
		"max execution statistics = 250\n"
		"monitoring user = mu\n"
		"monitoring debug = false\n"
		"[service]\n"
		"interface = 10.10.1.1\n"
		"http port = 0\n"
		"https port = 1234\n"
		"ssl server cert = /etc/opsi/opsiconfd.pem\n"
		"ssl server key = /etc/opsi/opsiconfd.pem\n"
		"accepted ciphers =\n"
		"[session]\n"
		"session name = OPSISID\n"
		"verify ip = yes\n"
		"update ip = no\n"
		"max inactive interval = 111\n"
		"max authentication failures = 222\n"
		"max sessions per ip = 333\n"
		"[directories]\n"
		"/ = /usr/share/opsiconfd/static (noauth)\n"
		"configed = /usr/lib/configed (noauth)\n"
	), encoding="utf-8")

	with patch("opsiconfd.config.is_manager", lambda x: True):
		config = get_config(["--config-file", str(config_file)])

	data = config_file.read_text(encoding="utf-8")
	data = re.sub(r"^#.*\n?", "", data, flags=re.MULTILINE)
	assert data == (
		"backend-config-dir = /backend/config/dir\n"
		"dispatch-config-file = /dispatch/config/file\n"
		"extension-config-dir = /extension/config/dir\n"
		"acl-file = /acl/file\n"
		"admin-networks = 10.10.0.0/16\n"
		"log-file = /log/file\n"
		"log-level = 1\n"
		"monitoring-user = mu\n"
		"interface = 10.10.1.1\n"
		"port = 1234\n"
		"verify-ip = true\n"
		"update-ip = false\n"
		"session-lifetime = 111\n"
		"max-auth-failures = 222\n"
		"max-session-per-ip = 333\n"
		"\n"
	)
	assert config.backend_config_dir == "/backend/config/dir"
	assert config.dispatch_config_file == "/dispatch/config/file"
	assert config.extension_config_dir == "/extension/config/dir"
	assert config.acl_file == "/acl/file"
	assert config.admin_networks == ["10.10.0.0/16"]
	assert config.log_file == "/log/file"
	assert config.symlink_logs is False
	assert config.log_level == 1
	assert config.monitoring_user == "mu"
	assert config.interface == "10.10.1.1"
	assert config.port == 1234
	assert config.verify_ip is True
	assert config.update_ip is False
	assert config.session_lifetime == 111
	assert config.max_auth_failures == 222
	assert config.max_session_per_ip == 333

	config_file.write_text("xxx\nyyy\n")
	config = get_config(["--config-file", str(config_file)])
	config._upgrade_config_files()  # pylint: disable=protected-access
	assert config_file.read_text(encoding="utf-8") == "xxx\nyyy\n"


def test_update_config_files(tmp_path):
	config_file = tmp_path / "opsiconfd.conf"
	config_file.write_text((
		"# comment\n"
		"log-level = 1\n"
		"monitoring-debug = yes\n"
		"\n"
	), encoding="utf-8")

	config = get_config(["--config-file", str(config_file)])
	config._update_config_files()  # pylint: disable=protected-access

	data = config_file.read_text(encoding="utf-8")
	assert data == (
		"# comment\n"
		"log-level = 1\n"
		"\n"
	)


def test_set_config_in_config_file(tmp_path):
	config_file = tmp_path / "opsiconfd.conf"
	config_file.write_text((
		"# comment\n"
		"log-level = 1\n"
		"\n"
	), encoding="utf-8")

	config = get_config(["--config-file", str(config_file)])
	grafana_internal_url = "redis://username:password@hostname:123/path"
	config.set_config_in_config_file("grafana-internal-url", grafana_internal_url)

	data = config_file.read_text(encoding="utf-8")
	assert data == (
		"# comment\n"
		"log-level = 1\n"
		"\n"
		f"grafana-internal-url = {grafana_internal_url}\n"
	)

	grafana_internal_url = "redis://username:password@hostname:123/new-path"
	config.set_config_in_config_file("grafana-internal-url", grafana_internal_url)

	data = config_file.read_text(encoding="utf-8")
	assert data == (
		"# comment\n"
		"log-level = 1\n"
		"\n"
		f"grafana-internal-url = {grafana_internal_url}\n"
	)
	config.reload()
	assert config.grafana_internal_url == grafana_internal_url
