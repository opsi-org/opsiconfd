# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
conftest
"""

import os
import pprint
import shutil
import sys
import threading
import time
import traceback
import warnings
from pathlib import Path
from tempfile import mkdtemp
from types import FrameType
from typing import Any, Callable, Coroutine, Generator
from unittest.mock import patch

import urllib3
from _pytest.config import Config
from _pytest.logging import LogCaptureHandler
from _pytest.main import Session
from _pytest.nodes import Item
from pluggy._result import Result
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

running_item: Callable | Coroutine | None = None


def signal_handler(self: Manager, signum: int, frame: FrameType | None) -> None:  # pylint: disable=unused-argument
	sys.exit(1)


Manager.orig_signal_handler = Manager.signal_handler  # type: ignore[attr-defined]
Manager.signal_handler = signal_handler  # type: ignore[assignment]


def emit(*args: Any, **kwargs: Any) -> None:  # pylint: disable=unused-argument
	pass


LogCaptureHandler.emit = emit  # type: ignore[assignment]


@hookimpl()
def pytest_sessionstart(session: Session) -> None:  # pylint: disable=unused-argument
	# print(sys.argv)
	if len(sys.argv) >= 2 and sys.argv[1] == "discover":
		# vscode test discovery running
		return

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

	def stderr_close() -> None:
		print("sys.stderr.close called!", file=sys.stderr)
		print("Running item:", running_item, file=sys.stderr)
		traceback.print_stack(file=sys.stderr)

	sys.stderr.close = stderr_close  # type: ignore[method-assign]

	def stdout_close() -> None:
		print("sys.stdout.close called!", file=sys.stderr)
		print("Running item:", running_item, file=sys.stderr)
		traceback.print_stack(file=sys.stderr)

	sys.stdout.close = stdout_close  # type: ignore[method-assign]

	# return
	print("Drop database")
	try:
		mysql = MySQLConnection()
		with mysql.connection():
			drop_database(mysql)
	except Exception:  # pylint: disable=broad-except
		pass
	print("Setup database")
	setup_mysql(explicit=True)
	print("Setup backend")
	setup_backend()

	with patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None), patch("opsiconfd.ssl.install_ca", lambda x: None):
		print("Setup SSL")
		setup_ssl()

	print("Setup application")
	Worker._instance = Worker("pytest", 1)  # pylint: disable=protected-access
	application_setup()


@hookimpl()
def pytest_sessionfinish(session: Session, exitstatus: int) -> None:  # pylint: disable=unused-argument
	# print(sys.argv)
	if len(sys.argv) >= 2 and sys.argv[1] == "discover":
		# vscode test discovery running
		return

	ssl_dir = os.path.dirname(_config.ssl_ca_key)
	if os.path.exists(ssl_dir):
		try:
			shutil.rmtree(ssl_dir)
		except PermissionError:
			pass

	sync_clean_redis()

	running_threads = [t for t in threading.enumerate() if t.name != "MainThread"]
	if running_threads:
		text = "\n".join([str(t) for t in running_threads if t.is_alive()])
		print(f"ERROR\nRunning threads on sessionfinish:\n{text}")
		if exitstatus == 0:
			sys.exit(1)


@hookimpl()
def pytest_runtest_setup(item: Item) -> None:
	# Called to perform the setup phase for a test item.
	grafana_available = GRAFANA_AVAILABLE
	for marker in item.iter_markers():
		if marker.name == "grafana_available" and not grafana_available:
			skip("Grafana not available")


@hookimpl(hookwrapper=True)
def pytest_pyfunc_call(pyfuncitem: Callable | Coroutine) -> Generator[None, Result, None]:
	start_threads = set(threading.enumerate())

	global running_item  # pylint: disable=global-statement
	running_item = pyfuncitem

	outcome: Result = yield

	running_item = None
	_result = outcome.get_result()  # Will raise if outcome was exception

	for wait in range(5):
		running_threads = (
			set(
				t
				for t in threading.enumerate()
				if t.is_alive()
				# and t.name != "AnyIO worker thread"
				and "ThreadPoolExecutor" not in str((getattr(t, "_args", None) or [None])[0])
			)
			- start_threads
		)
		if not running_threads:
			break
		if wait >= 10:
			print("Running threads after test:", file=sys.stderr)
			for thread in running_threads:
				print(thread.__dict__, file=sys.stderr)
			outcome.force_exception(RuntimeError(f"Running threads after test: {running_threads}"))
			break
		time.sleep(1)


@hookimpl()
def pytest_configure(config: Config) -> None:
	# https://pypi.org/project/pytest-asyncio
	# When the mode is auto, all discovered async tests are considered
	# asyncio-driven even if they have no @pytest.mark.asyncio marker.
	config.option.asyncio_mode = "auto"
	config.addinivalue_line("markers", "grafana_available: mark test to run only if a local grafana instance is available")


@fixture(autouse=True)
def disable_insecure_request_warning() -> None:
	warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
