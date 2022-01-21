# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
redis tests
"""

import pytest

from opsiconfd.utils import async_redis_client


@pytest.mark.asyncio
async def test_async_redis():
	redis = await async_redis_client()
	async with await redis.pipeline() as pipe:
		pipe.scan_iter("opsiconfd:*")
		await pipe.execute()
