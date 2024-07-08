# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test main
"""

import argparse
import json
import signal
import threading
import time
from logging import LogRecord
from pathlib import Path
from unittest.mock import patch

import pytest  # type: ignore[import]
from _pytest.capture import CaptureFixture
from opsicommon import __version__ as python_opsi_common_version

from opsiconfd import __version__
from opsiconfd.logging import RedisLogHandler
from opsiconfd.main import main
from opsiconfd.main.log_viewer import stop_log_viewer
from opsiconfd.utils import get_manager_pid

from .utils import Config, get_config


def test_version(capsys: CaptureFixture[str]) -> None:
	with get_config({"version": True}):
		main()
	captured = capsys.readouterr()
	assert captured.out == f"{__version__} [python-opsi-common={python_opsi_common_version}]\n"


def test_get_config(capsys: CaptureFixture[str]) -> None:
	with get_config({"action": "get-config"}) as conf:
		main()
		captured = capsys.readouterr()
		conf_out = json.loads(captured.out)
		assert conf_out == conf.items()


@pytest.mark.parametrize(
	"set_configs, expected_conf, expected_exc, expected_exc_match, on_change",
	[
		(["websocket_open_timeout = invalid"], [], argparse.ArgumentError, "invalid int value: 'invalid'", None),
		(
			[" websocket_open_timeout= 10", "admin-networks = 10.10.99.0/24"],
			["websocket-open-timeout = 10", "admin-networks = [10.10.99.0/24, 127.0.0.1/32]"],
			None,
			None,
			"reload",
		),
		(
			["networks = [10.10.88.0/24, 10.10.99.0/24]", "zeroconf=False"],
			["networks = [10.10.88.0/24, 10.10.99.0/24, 127.0.0.1/32]", "zeroconf = false"],
			None,
			None,
			"restart",
		),
	],
)
def test_set_config(
	tmp_path: Path,
	set_configs: list[str],
	expected_conf: list[str],
	expected_exc: type[Exception] | None,
	expected_exc_match: str | None,
	on_change: str | None,
) -> None:
	conf_file = tmp_path / "opsiconfd.conf"
	parse_args_called_with_ignore_env = None
	restart_opsiconfd_if_running_called = False
	reload_opsiconfd_if_running_called = False

	def _parse_args(self: Config, ignore_env: bool) -> None:
		nonlocal parse_args_called_with_ignore_env
		parse_args_called_with_ignore_env = ignore_env

	def restart_opsiconfd_if_running() -> None:
		nonlocal restart_opsiconfd_if_running_called
		restart_opsiconfd_if_running_called = True

	def reload_opsiconfd_if_running() -> None:
		nonlocal reload_opsiconfd_if_running_called
		reload_opsiconfd_if_running_called = True

	with (
		patch("opsiconfd.config.Config._parse_args", _parse_args),
		patch("opsiconfd.main.config.restart_opsiconfd_if_running", restart_opsiconfd_if_running),
		patch("opsiconfd.main.config.reload_opsiconfd_if_running", reload_opsiconfd_if_running),
		get_config({"config-file": str(conf_file), "action": "set-config", "set_configs": set_configs, "on_change": on_change}),
	):
		if expected_exc:
			with pytest.raises(expected_exc, match=expected_exc_match or ""):
				main()
		else:
			main()
			if expected_conf:
				lines = conf_file.read_text().split("\n")
				for line in expected_conf:
					assert line in lines
		assert parse_args_called_with_ignore_env is True
		if on_change == "restart":
			assert restart_opsiconfd_if_running_called is True
		elif on_change == "reload":
			assert reload_opsiconfd_if_running_called is True


def test_setup() -> None:
	with patch("opsiconfd.setup.setup") as mock_setup:
		with get_config({"action": "setup"}):
			main()
			mock_setup.assert_called_once_with(explicit=True)


def test_log_viewer() -> None:
	with get_config({"action": "log-viewer"}):
		thread = threading.Thread(target=main, daemon=True)
		thread.start()
		time.sleep(1)
		handler = RedisLogHandler()
		handler.emit(LogRecord(name="test-logger", level=10, pathname="-", lineno=1, msg="test-record", args=None, exc_info=None))
		time.sleep(1)
		handler.stop()
		stop_log_viewer()


def test_reload() -> None:
	mpid = get_manager_pid()
	if mpid:
		with patch("os.kill") as mock_kill:
			with get_config({"action": "reload"}):
				main()
				mock_kill.assert_called_once_with(mpid, signal.SIGHUP)


def test_force_stop() -> None:
	mpid = get_manager_pid()
	if mpid:
		with patch("os.kill") as mock_kill:
			with get_config({"action": "force-stop"}):
				main()
				mock_kill.assert_called_with(mpid, signal.SIGINT)
				assert mock_kill.call_count == 2
