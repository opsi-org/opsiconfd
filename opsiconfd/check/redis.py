# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from opsiconfd.check.cache import check_cache
from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult, exc_to_result
from opsiconfd.logging import logger
from opsiconfd.redis import decode_redis_result, redis_client

MEMORY_USAGE_WARN = 300_000_000
MEMORY_USAGE_ERR = 500_000_000


@check_cache("redis")
def check_redis() -> CheckResult:
	"""
	## Redis server

	Checks whether the Redis server is available and whether the RedisTimeSeries module is loaded.
	If the server is not available or the module is not loaded, this is considered an error.
	Also checks whether the memory usage is not too high.
	"""
	result = CheckResult(
		check_id="redis",
		check_name="Redis server",
		check_description="Check Redis server state",
		message="No Redis issues found.",
	)
	with exc_to_result(result):
		redis = redis_client(timeout=5, test_connection=True)
		result.add_partial_result(
			PartialCheckResult(
				check_id="redis:connection",
				check_name="Redis connection",
				check_status=CheckStatus.OK,
				message="Connection to Redis is working.",
			)
		)

		partial_result = PartialCheckResult(
			check_id="redis:timeseries",
			check_name="RedisTimeSeries module",
			check_status=CheckStatus.ERROR,
			message="RedisTimeSeries not loaded.",
		)

		redis_info = decode_redis_result(redis.execute_command("INFO"))
		logger.debug("Redis info: %s", redis_info)
		for module in redis_info.get("modules", []):
			if module["name"] == "timeseries":
				partial_result.check_status = CheckStatus.OK
				partial_result.message = f"RedisTimeSeries version {module['ver']!r} is loaded."
				partial_result.details = {"version": module["ver"]}
			result.add_partial_result(partial_result)

		partial_result = PartialCheckResult(
			check_id="redis:memory_usage",
			check_name="Redis memory usage",
			check_status=CheckStatus.OK,
		)
		info = redis.execute_command("INFO")
		if info["used_memory"] >= MEMORY_USAGE_ERR:
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"Redis memory usage is too high: {info['used_memory_human']}"
		elif info["used_memory"] >= MEMORY_USAGE_WARN:
			partial_result.check_status = CheckStatus.WARNING
			partial_result.message = f"Redis memory usage is high: {info['used_memory_human']}"
		else:
			partial_result.message = f"Redis memory usage is OK: {info['used_memory_human']}"
		result.add_partial_result(partial_result)

		if result.check_status != CheckStatus.OK:
			result.message = "Some issues found with Redis."
	return result
