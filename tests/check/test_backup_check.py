# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import time

import pytest

import opsiconfd.check.backup  # noqa: F401
from opsiconfd.check.cache import check_cache_clear
from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.config import config
from opsiconfd.redis import redis_client
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	sync_clean_redis,
	test_client,
)

DEPRECATED_METHOD = "getClientIds_list"


@pytest.fixture(autouse=True)
def cache_clear() -> None:
	check_cache_clear("all")


def test_check_backup(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	sync_clean_redis()
	# backup check should fail. No backup was created.

	result = check_manager.get("opsi_backup").run(use_cache=False)
	assert result.check_status == CheckStatus.ERROR

	# create a backup
	rpc = {"id": 1, "method": "service_createBackup", "params": [False, False, False]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	# backup check should pass. A backup was created.
	result = check_manager.get("opsi_backup").run(use_cache=False)
	assert result.check_status == CheckStatus.OK

	redis = redis_client()
	# remove backup key so check should fail again
	redis.delete(config.redis_key("stats") + ":backup")

	time.sleep(1)

	result = check_manager.get("opsi_backup").run(use_cache=False)
	assert result.check_status == CheckStatus.ERROR
