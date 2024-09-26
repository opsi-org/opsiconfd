# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import opsiconfd.check.backend  # noqa: F401
from opsiconfd.check.common import CheckStatus, check_manager
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	test_client,
)


def test_check_depotservers(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	rpc = {
		"id": 1,
		"method": "host_createOpsiDepotserver",
		"params": [
			"depot1-check.opsi.org",
			None,
			"file:///some/path/to/depot",
			"smb://172.17.0.101/opsi_depot",
			None,
			"file:///some/path/to/repository",
			"webdavs://172.17.0.101:4447/repository",
		],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	result = check_manager.get("depotservers").run(use_cache=False)
	assert result.check_status == CheckStatus.ERROR
