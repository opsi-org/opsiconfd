# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.main
"""

import warnings
from unittest.mock import patch

from opsiconfd.application.main import BaseMiddleware

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	clean_redis,
	test_client,
)


def test_http_1_0_warning(test_client):  # pylint: disable=redefined-outer-name
	orig_call = BaseMiddleware.__call__

	async def mock_call(self, scope, receive, send):
		scope["http_version"] = "1.0"
		return await orig_call(self, scope, receive, send)

	with patch("opsiconfd.application.main.BaseMiddleware.__call__", mock_call):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)

		with warnings.catch_warnings(record=True) as warns:
			test_client.get("/")
			assert len(warns) > 0
			for warn in warns:
				assert "is using http version 1.0" in str(warn.message)
