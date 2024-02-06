# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application status
"""

from unittest import mock

from opsicommon import __version__ as python_opsi_common_version  # type: ignore[import]

from opsiconfd import __version__

from .utils import OpsiconfdTestClient, test_client  # noqa: F401


def test_status_overview(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	status = test_client.get("/status")
	assert status.status_code == 200

	status_list = status._content.decode("utf-8").split("\n")
	assert status_list[0] == "status: ok"
	assert status_list[1] == f"version: {__version__} [python-opsi-common={python_opsi_common_version}]"
	assert status_list[5] == "redis-status: ok"
	assert status_list[6] == "redis-error: "


def test_status_overview_redis_error(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with mock.patch("redis.asyncio.client.Redis.execute_command", side_effect=Exception("Redis test error")):
		status = test_client.get("/status")
	assert status.status_code == 200

	status_list = status._content.decode("utf-8").split("\n")
	print(status_list)
	assert status_list[0] == "status: error"
	assert status_list[1] == f"version: {__version__} [python-opsi-common={python_opsi_common_version}]"
	assert status_list[5] == "redis-status: error"
	assert status_list[6] == "redis-error: Redis test error"
