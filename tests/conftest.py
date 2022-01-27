# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
conftest
"""

import asyncio
import warnings
import contextvars
from unittest.mock import patch
import urllib3

from fastapi.testclient import TestClient
import pytest
from _pytest.logging import LogCaptureHandler

from opsiconfd.backend import BackendManager
from opsiconfd.application.main import app, application_setup


def emit(*args, **kwargs) -> None:  # pylint: disable=unused-argument
	pass


LogCaptureHandler.emit = emit


BackendManager.default_config = {
	"backendConfigDir": "tests/opsi-config/backends",
	"dispatchConfigFile": "tests/opsi-config/backendManager/dispatch.conf"
}


@pytest.hookimpl()
def pytest_configure(config):
	# https://pypi.org/project/pytest-asyncio
	# When the mode is auto, all discovered async tests are considered
	# asyncio-driven even if they have no @pytest.mark.asyncio marker.
	config.option.asyncio_mode = "auto"


@pytest.fixture(scope='session')
def event_loop():
	"""Create an instance of the default event loop for each test case."""
	loop = asyncio.get_event_loop_policy().new_event_loop()
	yield loop
	loop.close()


@pytest.fixture(autouse=True)
def disable_insecure_request_warning():
	warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)


@pytest.fixture()
def test_client():
	application_setup()
	client = TestClient(app)
	client.context = None

	def get_client_address(self, scope):  # pylint: disable=unused-argument
		return ("127.0.0.1", 12345)

	def before_send(self, scope, receive, send):  # pylint: disable=unused-argument
		# Get the context out for later use
		client.context = contextvars.copy_context()

	with patch("opsiconfd.application.main.BaseMiddleware.get_client_address", get_client_address):
		with patch("opsiconfd.application.main.BaseMiddleware.before_send", before_send):
			yield client
