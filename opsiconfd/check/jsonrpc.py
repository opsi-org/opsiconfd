# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""

from __future__ import annotations

from datetime import datetime, timezone

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult, exc_to_result
from opsiconfd.config import config
from opsiconfd.redis import decode_redis_result, redis_client


def check_deprecated_calls() -> CheckResult:
	"""
	## Deprecated RPCs

	Among other things, opsi stores calls to methods marked as deprecated in Redis.
	This check looks whether such calls have been made and then issues a warning.
	The message also states which client agent called the API method.
	"""
	result = CheckResult(
		check_id="deprecated_calls",
		check_name="Deprecated RPCs",
		check_description="Check use of deprecated RPC methods",
		message="No deprecated method calls found.",
	)
	with exc_to_result(result):
		backend = get_unprotected_backend()
		redis_prefix_stats = config.redis_key("stats")
		deprecated_methods = 0
		with redis_client(timeout=5) as redis:
			methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
			for method_name in methods:
				method_name = method_name.decode("utf-8")
				calls = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:count"))
				if not calls:
					redis.srem(f"{redis_prefix_stats}:rpcs:deprecated:methods", method_name)
					continue
				deprecated_methods += 1
				interface = backend.get_method_interface(method_name)
				applications = decode_redis_result(redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:clients"))
				last_call = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:last_call"))
				last_call_dt = datetime.fromisoformat(last_call.replace("Z", "")).astimezone(timezone.utc)
				last_call = last_call_dt.strftime("%Y-%m-%d %H:%M:%S")
				message = f"Deprecated method {method_name!r} was called {calls} times.\n"
				if interface and interface.drop_version:
					message += f"The method will be dropped with opsiconfd version {interface.drop_version}.\n"
				message += f"Last call was {last_call}\nThe method was called from the following applications:\n"
				message += "\n".join([f"- {app}" for app in applications])
				result.add_partial_result(
					PartialCheckResult(
						check_id=f"deprecated_calls:{method_name}",
						check_name=f"Deprecated method {method_name!r}",
						check_status=CheckStatus.WARNING,
						message=message,
						upgrade_issue=interface.drop_version if interface else None,
						details={
							"method": method_name,
							"calls": calls,
							"last_call": last_call,
							"applications": list(applications),
							"drop_version": interface.drop_version if interface else None,
						},
					)
				)
		if deprecated_methods:
			result.message = f"Use of {deprecated_methods} deprecated methods found."
	return result
