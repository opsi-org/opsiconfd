# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""

from opsiconfd.check.common import CheckResult, CheckStatus, exc_to_result
from opsiconfd.logging import logger
from opsiconfd.redis import decode_redis_result, redis_client


def check_redis() -> CheckResult:
	"""
	## Redis server

	Checks whether the Redis server is available and whether the RedisTimeSeries module is loaded.
	If the server is not available or the module is not loaded, this is considered an error.
	"""
	result = CheckResult(
		check_id="redis",
		check_name="Redis server",
		check_description="Check Redis server state",
		details={"connection": False, "timeseries": False},
	)
	with exc_to_result(result):
		with redis_client(timeout=5, test_connection=True) as redis:
			result.details["connection"] = True
			redis_info = decode_redis_result(redis.execute_command("INFO"))
			logger.debug("Redis info: %s", redis_info)
			modules = [module["name"] for module in redis_info["modules"]]
			if "timeseries" not in modules:
				result.details["timeseries"] = False
				result.check_status = CheckStatus.ERROR
				result.message = "RedisTimeSeries not loaded."
			else:
				result.check_status = CheckStatus.OK
				result.message = "Redis is running and RedisTimeSeries is loaded."

	return result
