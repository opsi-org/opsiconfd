# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application status
"""

from unittest import mock

from OPSI import __version__ as python_opsi_version  # type: ignore[import]
from opsiconfd import __version__

from .utils import test_client  # pylint: disable=unused-import


def test_status_overview(test_client):  # pylint: disable=redefined-outer-name
	status = test_client.get("/status")
	assert status.status_code == 200

	status_list = status._content.decode("utf-8").split("\n")  # pylint: disable=protected-access
	assert status_list[0] == "status: ok"
	assert status_list[1] == f"version: {__version__} [python-opsi={python_opsi_version}]"
	assert status_list[5] == "redis-status: ok"
	assert status_list[6] == "redis-error: "


def test_status_overview_redis_error(test_client):  # pylint: disable=redefined-outer-name

	with mock.patch("aioredis.client.Redis.execute_command", side_effect=Exception("Redis test error")):
		status = test_client.get("/status")
	assert status.status_code == 200

	status_list = status._content.decode("utf-8").split("\n")  # pylint: disable=protected-access
	print(status_list)
	assert status_list[0] == "status: error"
	assert status_list[1] == f"version: {__version__} [python-opsi={python_opsi_version}]"
	assert status_list[5] == "redis-status: error"
	assert status_list[6] == "redis-error: Redis test error"
