# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.cache
"""

import time
from unittest.mock import patch

from opsiconfd.backend.rpc.cache import (
	rpc_cache_clear,
	rpc_cache_info,
	rpc_cache_load,
	rpc_cache_store,
)

from .utils import clean_redis  # pylint: disable=unused-import


def test_cache_store_load_clear_info() -> None:
	with patch("opsiconfd.backend.rpc.cache.REDIS_PREFIX", "opsiconfd:test_rpccache"):
		assert rpc_cache_load("cache1", "param1", param2=2) is None
		assert not rpc_cache_info()

		result_1_1 = {"some": "result", "to": "cache"}
		rpc_cache_store("cache1", result_1_1, "param1", param2=2)
		assert rpc_cache_load("cache1", "param1", param2=2) == result_1_1

		assert rpc_cache_load("cache1", "param1", 2) is None

		result_1_2 = {"some": "other_result", "list": [1, 2, 3]}
		rpc_cache_store("cache1", result_1_2, "param1", 2)

		result_2_1 = {"some": "other_result", "list": [1, 2, 3]}
		rpc_cache_store("cache2", result_2_1)

		assert rpc_cache_load("cache1", "param1", param2=2) == result_1_1
		assert rpc_cache_load("cache1", "param1", 2) == result_1_2
		assert rpc_cache_load("cache2") == result_2_1

		assert rpc_cache_info() == {"cache1": 2, "cache2": 1}
		rpc_cache_clear("cache1")
		assert rpc_cache_load("cache1", "param1", param2=2) is None
		assert rpc_cache_load("cache1", "param1", 2) is None
		assert rpc_cache_load("cache2") == result_2_1
		assert rpc_cache_info() == {"cache2": 1}

		rpc_cache_clear("cache2")
		assert rpc_cache_load("cache1", "param1", param2=2) is None
		assert rpc_cache_load("cache1", "param1", 2) is None
		assert rpc_cache_load("cache2") is None
		assert not rpc_cache_info()


def test_cache_expiration() -> None:
	with (
		patch("opsiconfd.backend.rpc.cache.REDIS_PREFIX", "opsiconfd:test_rpccache"),
		patch("opsiconfd.backend.rpc.cache.CACHE_EXPIRATION", 1),
	):
		result = b"DATA"
		assert rpc_cache_load("cache_test", param=True) is None
		rpc_cache_store("cache_test", result, param=True)
		assert rpc_cache_load("cache_test", param=True) == result
		time.sleep(2)
		assert rpc_cache_load("cache_test", param=True) is None
