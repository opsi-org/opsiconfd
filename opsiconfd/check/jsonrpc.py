# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """

# from __future__ import annotations

# from opsiconfd.backend import get_unprotected_backend
# from opsiconfd.check.common import Check, CheckResult, CheckStatus, PartialCheckResult, exc_to_result
from dataclasses import dataclass
from datetime import datetime, timezone

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager, exc_to_result
from opsiconfd.config import config
from opsiconfd.redis import decode_redis_result, redis_client


@dataclass()
class DeprecatedClassCheck(Check):
	id: str = "deprecated_calls"
	name: str = "Deprecated Check"
	description: str = "Deprecated Check"
	partial_check: bool = True
	method: str = "method"

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"deprecated_calls:{self.method}"
		self.name = f"{self.name} {self.method.capitalize()}"
		self.description = f"{self.description} for method {self.method!r}"

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Deprecated Check",
			check_status=CheckStatus.OK,
		)
		with exc_to_result(result):
			backend = get_unprotected_backend()
			redis_prefix_stats = config.redis_key("stats")
			redis = redis_client(timeout=5)

			calls = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{self.method}:count"))
			if not calls:
				redis.srem(f"{redis_prefix_stats}:rpcs:deprecated:methods", self.method)
				return result
			interface = backend.get_method_interface(self.method)
			applications = decode_redis_result(redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:{self.method}:clients"))
			last_call = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{self.method}:last_call"))
			last_call_dt = datetime.fromisoformat(last_call.replace("Z", "")).astimezone(timezone.utc)
			last_call = last_call_dt.strftime("%Y-%m-%d %H:%M:%S")
			message = f"Deprecated method {self.method!r} was called {calls} times.\n"
			if interface and interface.drop_version:
				message += f"The method will be dropped with opsiconfd version {interface.drop_version}.\n"
			message += f"Last call was {last_call}\nThe method was called from the following applications:\n"
			message += "\n".join([f"- {app}" for app in applications])

			result = CheckResult(
				check=self,
				check_status=CheckStatus.WARNING,
				message=message,
				upgrade_issue=interface.drop_version if interface else None,
				details={
					"method": self.method,
					"calls": calls,
					"last_call": last_call,
					"applications": list(applications),
					"drop_version": interface.drop_version if interface else None,
				},
			)

		return result


@dataclass()
class DeprecatedCallsCheck(Check):
	id: str = "deprecated_calls"
	name: str = "Deprecated RPCs"
	description: str = "Check use of deprecated RPC methods"
	documentation: str = """
## Deprecated RPCs

Among other things, opsi stores calls to methods marked as deprecated in Redis.
This check looks whether such calls have been made and then issues a warning.
The message also states which client agent called the API method.
"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No deprecated method calls found.",
			check_status=CheckStatus.OK,
		)

		return result


deprecated_calls_check = DeprecatedCallsCheck()

redis = redis_client(timeout=5)
redis_prefix_stats = config.redis_key("stats")
methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
for method_name in methods:
	method_name = method_name.decode("utf-8")
	deprecated_calls_check.add_partial_checks(DeprecatedClassCheck(method=method_name))
check_manager.register(deprecated_calls_check)
