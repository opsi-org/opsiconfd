# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
Test opsiconfd.manager
"""

import asyncio
import signal
import time
from typing import Generator
from unittest.mock import patch

import pytest

from opsiconfd.manager import Manager
from opsiconfd.server import Server

from .utils import get_config, reset_singleton


@pytest.fixture()
def manager() -> Generator[Manager, None, None]:  # pylint: disable=redefined-outer-name
	with (
		patch("opsiconfd.server.Server.run", lambda *args, **kwargs: None),
		patch("opsiconfd.manager.init_logging", lambda *args, **kwargs: None),
		patch("opsiconfd.manager.register_opsi_services", lambda *args, **kwargs: asyncio.sleep(0.1)),
		patch("opsiconfd.manager.unregister_opsi_services", lambda *args, **kwargs: asyncio.sleep(0.1)),
	):
		reset_singleton(Manager)
		man = Manager()
		man.run()
		try:
			yield man
		finally:
			man.stop()
			man._async_main_stopped.wait(5)  # pylint: disable=protected-access


def test_manager_signals(manager: Manager) -> None:  # pylint: disable=redefined-outer-name
	# signal_handler is replaced in conftest

	test_reload = False

	def reload() -> None:
		nonlocal test_reload
		test_reload = True

	setattr(manager, "reload", reload)

	manager._last_reload = 0  # pylint: disable=protected-access
	manager.orig_signal_handler(signal.SIGHUP, None)  # type: ignore[attr-defined]
	assert test_reload is True

	test_reload = False
	manager._last_reload = int(time.time())  # pylint: disable=protected-access
	manager.orig_signal_handler(signal.SIGHUP, None)  # type: ignore[attr-defined]
	assert test_reload is False

	test_stop = ""

	def stop(force: bool = False) -> None:
		nonlocal test_stop
		test_stop = "force" if force else "normal"

	setattr(manager._server, "stop", stop)  # pylint: disable=protected-access
	manager.orig_signal_handler(signal.SIGKILL, None)  # type: ignore[attr-defined]
	assert manager._should_stop is True  # pylint: disable=protected-access
	assert test_stop == "normal"
	time.sleep(0.1)
	manager.orig_signal_handler(signal.SIGKILL, None)  # type: ignore[attr-defined]
	assert manager._should_stop is True  # pylint: disable=protected-access
	assert test_stop == "force"


@pytest.mark.parametrize("cert_changed", (False, True))
def test_check_server_cert(manager: Manager, cert_changed: bool) -> None:  # pylint: disable=redefined-outer-name,unused-argument

	test_restarted = False

	def restart_workers(self: Server) -> None:  # pylint: disable=unused-argument
		nonlocal test_restarted
		test_restarted = True

	with (
		patch("opsiconfd.server.Server.restart_workers", restart_workers),
		patch("opsiconfd.manager.setup_server_cert", lambda: cert_changed),
	):
		with get_config({"ssl_server_cert_check_interval": 0.00001}):
			time.sleep(2)
			assert test_restarted == cert_changed
