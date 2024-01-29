# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.main
"""

import warnings
from datetime import datetime, timezone
from time import sleep, time
from unittest.mock import patch

from starlette.types import Receive, Scope, Send

from opsiconfd.application.main import BaseMiddleware

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_redis,
	test_client,
)


def test_http_1_0_warning(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	orig_call = BaseMiddleware.__call__

	async def mock_call(self: BaseMiddleware, scope: Scope, receive: Receive, send: Send) -> None:
		scope["http_version"] = "1.0"
		return await orig_call(self, scope, receive, send)

	with patch("opsiconfd.application.main.BaseMiddleware.__call__", mock_call):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)

		with warnings.catch_warnings(record=True) as warns:
			test_client.get("/")
			assert len(warns) > 0
			for warn in warns:
				assert "is using http version 1.0" in str(warn.message)


def test_server_date_header(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	res = test_client.get("/")
	server_date = res.headers["date"]
	assert server_date.endswith(" UTC")
	server_dt = datetime.strptime(server_date, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
	now = datetime.now(tz=timezone.utc)
	assert abs((now - server_dt).total_seconds()) < 2
	sleep(1)
	res = test_client.get("/")
	server_date = res.headers["date"]
	server_dt = datetime.strptime(server_date, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
	assert now < server_dt
