# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """

from dataclasses import dataclass

from redis.exceptions import ConnectionError as RedisConnectionError

from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager, exc_to_result
from opsiconfd.redis import decode_redis_result, redis_client

MEMORY_USAGE_WARN = 300_000_000
MEMORY_USAGE_ERR = 500_000_000


@dataclass()
class RedisMemoryUsageCheck(Check):
	id: str = "redis:memory_usage"
	name: str = "Redis memory usage"
	description: str = "Check whether the Redis memory usage is not too high."
	partial_check: bool = True
	documentation: str = """
		## Redis memory usage

		Checks whether the Redis memory usage is not too high.
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Redis memory usage is OK.",
			check_status=CheckStatus.OK,
		)
		with exc_to_result(result):
			redis = redis_client(timeout=5, test_connection=True)
			info = decode_redis_result(redis.execute_command("INFO"))
			if info["used_memory"] >= MEMORY_USAGE_ERR:
				result.check_status = CheckStatus.ERROR
				result.message = f"Redis memory usage is too high: {info['used_memory_human']}"
			elif info["used_memory"] >= MEMORY_USAGE_WARN:
				result.check_status = CheckStatus.WARNING
				result.message = f"Redis memory usage is high: {info['used_memory_human']}"
			else:
				result.message = f"Redis memory usage is OK: {info['used_memory_human']}"
		return result


@dataclass()
class RedisTimeseriesCheck(Check):
	id: str = "redis:timeseries"
	name: str = "RedisTimeSeries module"
	description: str = "Check whether the RedisTimeSeries module is loaded."
	partial_check: bool = True
	documentation: str = """
		## RedisTimeSeries module

		Checks whether the RedisTimeSeries module is loaded.
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="RedisTimeSeries not loaded.",
			check_status=CheckStatus.ERROR,
		)
		with exc_to_result(result):
			redis = redis_client(timeout=5, test_connection=True)
			redis_info = decode_redis_result(redis.execute_command("INFO"))
			for module in redis_info.get("modules", []):
				if module["name"] == "timeseries":
					result.message = f"RedisTimeSeries version {module['ver']!r} is loaded."
					result.check_status = CheckStatus.OK
					result.details = {"version": module["ver"]}
		return result


@dataclass()
class RedisCheck(Check):
	id: str = "redis"
	name: str = "Redis Server"
	description: str = "Check Redis server state."
	documentation: str = """
		## Redis server

		Checks whether the Redis server is available and whether the RedisTimeSeries module is loaded.
		If the server is not available or the module is not loaded, this is considered an error.
		Also checks whether the memory usage is not too high.
	"""
	status: CheckStatus = CheckStatus.OK
	message: str = "No Redis issues found."
	depot_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Cannot connect to Redis:",
			check_status=CheckStatus.OK,
		)
		try:
			redis_client(timeout=5, test_connection=True)
			result.message = "The connection to the Redis server does work."
			self.add_partial_checks(RedisTimeseriesCheck(), RedisMemoryUsageCheck())
		except RedisConnectionError as err:
			result.check_status = CheckStatus.ERROR
			result.message = f"Cannot connect to Redis: {err}"
		except Exception as err:
			result.check_status = CheckStatus.ERROR
			result.message = str(err)

		return result


redis_check = RedisCheck()
check_manager.register(redis_check)
