# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
conftest
"""

import asyncio
import os
import pprint
import shutil
import sys
import threading
import warnings
from pathlib import Path
from tempfile import mkdtemp
from types import FrameType
from typing import Any, Generator
from unittest.mock import patch

import urllib3
from _pytest.config import Config
from _pytest.logging import LogCaptureHandler
from _pytest.main import Session
from _pytest.nodes import Item
from pytest import fixture, hookimpl, skip

from opsiconfd.application.main import application_setup
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.mysql.schema import drop_database
from opsiconfd.config import config as _config
from opsiconfd.grafana import GRAFANA_DB, grafana_is_local
from opsiconfd.manager import Manager
from opsiconfd.setup import setup_backend, setup_mysql, setup_ssl
from opsiconfd.worker import Worker

from .utils import sync_clean_redis

GRAFANA_AVAILABLE = False


def signal_handler(self: Manager, signum: int, frame: FrameType | None) -> None:  # pylint: disable=unused-argument
	sys.exit(1)


Manager.orig_signal_handler = Manager.signal_handler  # type: ignore[attr-defined]
Manager.signal_handler = signal_handler  # type: ignore[assignment]


def emit(*args: Any, **kwargs: Any) -> None:  # pylint: disable=unused-argument
	pass


LogCaptureHandler.emit = emit  # type: ignore[assignment]


@hookimpl()
def pytest_sessionstart(session: Session) -> None:  # pylint: disable=unused-argument
	global GRAFANA_AVAILABLE  # pylint: disable=global-statement

	Path("tests/data/opsi-config/opsi.conf").unlink(missing_ok=True)
	_config.set_config_file("tests/data/default-opsiconfd.conf")
	_config.reload()

	# Need to use other redis key prefix to not interfere with an running opsiconfd with same test config
	_config._config.redis_prefix = "pytest"  # pylint: disable=protected-access

	sync_clean_redis()

	ssl_dir = mkdtemp()
	_config.ssl_ca_key = os.path.join(ssl_dir, "opsi-ca-key.pem")
	_config.ssl_ca_cert = os.path.join(ssl_dir, "opsi-ca-cert.pem")
	_config.ssl_server_key = os.path.join(ssl_dir, "opsiconfd-key.pem")
	_config.ssl_server_cert = os.path.join(ssl_dir, "opsiconfd-cert.pem")

	print("Config:")
	pprint.pprint(_config.items(), width=200)

	if grafana_is_local() and os.access(GRAFANA_DB, os.W_OK):
		GRAFANA_AVAILABLE = True

	# return

	print("Drop database")
	try:
		mysql = MySQLConnection()
		with mysql.connection():
			drop_database(mysql)
	except Exception:  # pylint: disable=broad-except
		pass
	print("Setup database")
	setup_mysql(full=True)
	print("Setup backend")
	setup_backend()

	with (patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None), patch("opsiconfd.ssl.install_ca", lambda x: None)):
		print("Setup SSL")
		setup_ssl()

	print("Setup application")
	Worker._instance = Worker("pytest", 1)  # pylint: disable=protected-access
	application_setup()


@hookimpl()
def pytest_sessionfinish(session: Session, exitstatus: int) -> None:  # pylint: disable=unused-argument
	ssl_dir = os.path.dirname(_config.ssl_ca_key)
	if os.path.exists(ssl_dir):
		try:
			shutil.rmtree(ssl_dir)
		except PermissionError:
			pass

	sync_clean_redis()

	running_threads = "\n".join([str(t) for t in threading.enumerate()])
	if running_threads:
		print(f"\nRunning threads on sessionfinish:\n{running_threads}")


@hookimpl()
def pytest_configure(config: Config) -> None:
	# https://pypi.org/project/pytest-asyncio
	# When the mode is auto, all discovered async tests are considered
	# asyncio-driven even if they have no @pytest.mark.asyncio marker.
	config.option.asyncio_mode = "auto"
	config.addinivalue_line("markers", "grafana_available: mark test to run only if a local grafana instance is available")


@hookimpl()
def pytest_runtest_setup(item: Item) -> None:
	grafana_available = GRAFANA_AVAILABLE
	for marker in item.iter_markers():
		if marker.name == "grafana_available" and not grafana_available:
			skip("Grafana not available")


@fixture()  # scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
	"""Create an instance of the default event loop for each test case."""
	loop = asyncio.get_event_loop_policy().new_event_loop()
	yield loop
	loop.close()


@fixture(autouse=True)
def disable_insecure_request_warning() -> None:
	warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)


@fixture(autouse=True)
def disable_redis_asyncio_deprecation_warning() -> None:
	# message="There is no current event loop", category=DeprecationWarning, module="redis.asyncio.connection", lineno=677
	warnings.filterwarnings(
		"ignore", category=DeprecationWarning, module="redis.asyncio.connection", message="There is no current event loop"
	)


@fixture(autouse=True)
def disable_warnings() -> None:
	# message="There is no current event loop", category=DeprecationWarning, module="redis.asyncio.connection", lineno=677
	warnings.filterwarnings(
		"ignore", category=DeprecationWarning, module="redis.asyncio.connection", message="There is no current event loop"
	)
