# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test main
"""

import signal
import threading
import time
from logging import LogRecord
from unittest.mock import patch

from _pytest.capture import CaptureFixture
from opsicommon import __version__ as python_opsi_common_version  # type: ignore[import]

from opsiconfd import __version__
from opsiconfd.logging import RedisLogHandler
from opsiconfd.main import main, stop_log_viewer
from opsiconfd.utils import get_manager_pid

from .utils import get_config


def test_version(capsys: CaptureFixture[str]) -> None:
	with get_config({"version": True}):
		main()
	captured = capsys.readouterr()
	assert captured.out == f"{__version__} [python-opsi-common={python_opsi_common_version}]\n"


def test_setup() -> None:
	with patch("opsiconfd.main.setup") as mock_setup:
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
