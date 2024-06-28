# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
config tests
"""

import os
from argparse import ArgumentTypeError
from pathlib import Path
from typing import Any, Type
from unittest.mock import patch
from threading import Thread
import pytest

from opsiconfd.config import ip_address, network_address, str2bool

from .utils import (  # noqa: F401
	OpsiconfdTestClient,
	get_config,
	test_client,
)


@pytest.mark.parametrize(
	"value, expected_value, exception",
	[
		("10.10.0.0/16", "10.10.0.0/16", None),
		("10.10.0.0/255.255.255.0", "10.10.0.0/24", None),
		("10.10.10.10/16", None, ArgumentTypeError),
		("10.10.10.10", "10.10.10.10/32", None),
		("fe80:0000::/10", "fe80::/10", None),
		("2001:0db8:1234:0000:0000:0000:0000:0000/48", "2001:db8:1234::/48", None),
	],
)
def test_network_address(value: Any, expected_value: Any, exception: Type[Exception] | None) -> None:
	if exception:
		with pytest.raises(exception):
			network_address(value)
	else:
		assert network_address(value) == expected_value


@pytest.mark.parametrize(
	"value, expected_value, exception",
	[
		("10.10.0.1", "10.10.0.1", None),
		("10.10.0.1/32", None, ArgumentTypeError),
		("2001:0db8:1234:0000:0000:0000:0000:0001", "2001:db8:1234::1", None),
		("::1", "::1", None),
		("127.0.0.1", "127.0.0.1", None),
	],
)
def test_ip_address(value: Any, expected_value: Any, exception: Type[Exception] | None) -> None:
	if exception:
		with pytest.raises(exception):
			ip_address(value)
	else:
		assert ip_address(value) == expected_value


@pytest.mark.parametrize(
	"value, expected_value",
	[("yes", True), ("y", True), ("true", True), ("1", True), (True, True), ("0", False), ("no", False), ("false", False), (False, False)],
)
def test_str2bool(value: Any, expected_value: bool) -> None:
	assert str2bool(value) is expected_value


@pytest.mark.parametrize(
	"arguments, config_name, expected_value",
	[
		(["--backend-config-dir", "/test"], "backend_config_dir", "/test"),
		(["--dispatch-config-file", "/filename"], "dispatch_config_file", "/filename"),
		(["--extension-config-dir", "/test"], "extension_config_dir", "/test"),
		(["--networks", "10.10.10.0/24", "10.10.20.0/24"], "networks", ["10.10.10.0/24", "10.10.20.0/24", "127.0.0.1/32"]),
		(["--admin-networks", "10.10.10.0/24", "10.10.20.0/24"], "admin_networks", ["10.10.10.0/24", "10.10.20.0/24", "127.0.0.1/32"]),
		(["--symlink-logs"], "symlink_logs", True),
	],
)
def test_cmdline(arguments: list[str], config_name: str, expected_value: Any) -> None:
	with get_config(arguments) as conf:
		assert getattr(conf, config_name) == expected_value


@pytest.mark.parametrize(
	"varname, value, config_name, expected_value",
	[
		("OPSICONFD_BACKEND_CONFIG_DIR", "/test", "backend_config_dir", "/test"),
		("OPSICONFD_DISPATCH_CONFIG_FILE", "/filename", "dispatch_config_file", "/filename"),
		("OPSICONFD_EXTENSION_CONFIG_DIR", "/test", "extension_config_dir", "/test"),
		("OPSICONFD_ADMIN_NETWORKS", "[10.10.10.0/24,10.10.20.0/24]", "admin_networks", ["10.10.10.0/24", "10.10.20.0/24", "127.0.0.1/32"]),
		("OPSICONFD_SYMLINK_LOGS", "yes", "symlink_logs", True),
		("OPSICONFD_SSL_CA_KEY_PASSPHRASE", "", "ssl_ca_key_passphrase", None),
		("OPSICONFD_SSL_SERVER_KEY_PASSPHRASE", "", "ssl_server_key_passphrase", None),
	],
)
def test_environment_vars(varname: str, value: str, config_name: str, expected_value: Any) -> None:
	os.environ[varname] = value
	with get_config([], with_env=True) as conf:
		try:
			assert getattr(conf, config_name) == expected_value
		finally:
			del os.environ[varname]


@pytest.mark.parametrize(
	"varname, value, config_name, expected_value",
	[
		("backend-config-dir", "/test", "backend_config_dir", "/test"),
		("dispatch-config-file", "/filename", "dispatch_config_file", "/filename"),
		("extension-config-dir", "/test", "extension_config_dir", "/test"),
		("admin-networks", "[10.10.10.0/24,10.10.20.0/24]", "admin_networks", ["10.10.10.0/24", "10.10.20.0/24", "127.0.0.1/32"]),
		("symlink-logs", "1", "symlink_logs", True),
		("symlink-logs", "false", "symlink_logs", False),
		("symlink-logs", "no", "symlink_logs", False),
	],
)
def test_config_file(tmp_path: Path, varname: str, value: str, config_name: str, expected_value: Any) -> None:
	conf_file = tmp_path / "opsiconfd.conf"
	conf_file.write_text(f"{varname} = {value}")
	with get_config(["--config-file", str(conf_file)]) as conf:
		assert getattr(conf, config_name) == expected_value


def test_help() -> None:
	text = ""

	def print_message(self: Any, message: str, file: Any = None) -> None:
		nonlocal text
		text = message

	with patch("argparse.ArgumentParser._print_message", print_message), patch("sys.stdout.isatty", lambda: True):
		with pytest.raises(SystemExit):
			with get_config(["--help"]):
				pass
		assert "Set maximum log message length" not in text

		text = ""
		with pytest.raises(SystemExit):
			with get_config(["--ex-help"]):
				pass
		assert "Set maximum log message length" in text


def test_update_config_files(tmp_path: Path) -> None:
	config_file = tmp_path / "opsiconfd.conf"
	config_file.write_text(("# comment\nlog-level = 1\nmonitoring-debug = yes\n\n"), encoding="utf-8")

	with get_config(["--config-file", str(config_file)]) as conf:
		conf._update_config_file()

	data = config_file.read_text(encoding="utf-8")
	assert data == ("# comment\nlog-level = 1\n\n")


@pytest.mark.parametrize(
	"old_lines, configs1, new_lines1, configs2, new_lines2",
	(
		(
			("# comment\n", "  other-value = [1, 2, 3] \n\n", "  # other comment\n", "log-level = 1\n", "\n"),
			{"grafana-internal-url": "redis://username:password@hostname:123/path"},
			(
				"# comment\n",
				"  other-value = [1, 2, 3] \n\n",
				"  # other comment\n",
				"log-level = 1\n",
				"\n",
				"grafana-internal-url = redis://username:password@hostname:123/path\n",
			),
			{"grafana-internal-url": "redis://username:password@hostname:123/new-path"},
			(
				"# comment\n",
				"  other-value = [1, 2, 3] \n\n",
				"  # other comment\n",
				"log-level = 1\n",
				"\n",
				"grafana-internal-url = redis://username:password@hostname:123/new-path\n",
			),
		),
		(
			("log-level = 1",),
			{"grafana-internal-url": "redis://username:password@hostname:123/path"},
			(
				"log-level = 1\n",
				"grafana-internal-url = redis://username:password@hostname:123/path\n",
			),
			{"grafana-internal-url": "redis://username:password@hostname:123/new-path"},
			(
				"log-level = 1\n",
				"grafana-internal-url = redis://username:password@hostname:123/new-path\n",
			),
		),
		(
			("",),
			{"grafana-internal-url": "redis://username:password@hostname:123/path"},
			("grafana-internal-url = redis://username:password@hostname:123/path\n",),
			{"grafana-internal-url": "redis://username:password@hostname:123/new-path"},
			("grafana-internal-url = redis://username:password@hostname:123/new-path\n",),
		),
	),
)
def test_set_config_in_config_file(
	tmp_path: Path,
	old_lines: tuple[str],
	configs1: dict[str, str],
	new_lines1: tuple[str],
	configs2: dict[str, str],
	new_lines2: tuple[str],
) -> None:
	config_file = tmp_path / "opsiconfd.conf"
	config_file.write_text("".join(old_lines), encoding="utf-8")

	class SetConfigThread(Thread):
		def __init__(self, func: str) -> None:
			super().__init__(daemon=True)
			self.func = func
			self.err: Exception | None = None

		def run(self) -> None:
			try:
				getattr(self, self.func)()
			except Exception as err:
				self.err = err

		def set_configs1(self) -> None:
			for key, val in configs1.items():
				conf.set_config_in_config_file(key, val)

			data = config_file.read_text(encoding="utf-8")
			assert data == "".join(new_lines1)

		def set_configs2(self) -> None:
			for key, val in configs2.items():
				conf.set_config_in_config_file(key, val)

			data = config_file.read_text(encoding="utf-8")
			assert data == "".join(new_lines2)

	with get_config(["--config-file", str(config_file)]) as conf:
		for func in ("set_configs1", "set_configs2"):
			print("---------------------------------------------------------")
			print("Running", func)
			threads: list[SetConfigThread] = []
			for _ in range(20):
				threads.append(SetConfigThread(func=func))
			for thread in threads:
				thread.start()
			for thread in threads:
				thread.join()
				if thread.err:
					print(f"Error in thread ({func})")
					raise thread.err


def test_disabled_features(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.get("/status")
	assert res.status_code == 200
	with get_config({"disabled_features": ["status-page"]}):
		res = test_client.get("/status")
		assert res.status_code == 404
