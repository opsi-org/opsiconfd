# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.check.cache
"""

from collections import defaultdict
from functools import wraps
from typing import Any, Callable

from msgspec.msgpack import decode, encode

from opsiconfd.check.common import CheckResult, PartialCheckResult
from opsiconfd.check.const import CHECKS
from opsiconfd.logging import logger
from opsiconfd.redis import delete_recursively, redis_client


CACHE_EXPIRATION = 24 * 3600  # In seconds

def check_cache_store(cache_id: str, result: Any, expiration: int = CACHE_EXPIRATION) -> None:
	if cache_id not in CHECKS:
		logger.error("Invalid check cache id: %s", cache_id)
	redis_key = f"opsiconfd:checkcache:{cache_id}"
	logger.debug("Check cache store: %s", redis_key)
	redis_client().set(redis_key, encode(result), ex=expiration)


def check_cache_load(cache_id: str) -> Any:
	redis_key = f"opsiconfd:checkcache:{cache_id}"
	msgpack_data = redis_client().get(redis_key)
	if msgpack_data:
		logger.debug("Check cache hit: %s", redis_key)
		return decode(msgpack_data)
	logger.debug("Check cache miss: %s", redis_key)
	return None


def check_cache_clear(cache_id: str | None = None) -> Any:
	logger.debug("Clearing check cache: %s", cache_id)
	redis_key = "opsiconfd:checkcache"
	if cache_id != "all":
		redis_key = f"{redis_key}:{cache_id}"
	delete_recursively(redis_key)


def check_cache_info() -> dict[str, int]:
	info: dict[str, int] = defaultdict(int)
	prefix = "opsiconfd:checkcache:"
	for key in redis_client().scan_iter(f"{prefix}*"):
		rel = key.decode("utf-8").removeprefix(prefix)
		if ":" in rel:
			cache_name, _ = rel.split(":", 1)
			info[cache_name] += 1
	return info


def check_cache(
	func: Callable | None = None,
	/,
	*,
	check_id: str | None = None,
	cache_expiration: int = CACHE_EXPIRATION,
	clear_cache: str | None = None,
) -> Callable:
	if check_id is not None:
		return
	def decorator(func: Callable) -> Callable:
		@wraps(func)
		def wrapper(*args: Any, **kwargs: Any) -> Any:
			if clear_cache:
				check_cache_clear(clear_cache)
				return func(*args, **kwargs)
			else:
				result = check_cache_load(check_id, *args[1:], **kwargs)
				if result is not None:
					check_result = CheckResult(**result)
					check_result.partial_results = []
					for partial_result in result.get("partial_results", []):
						partial_result = PartialCheckResult(**partial_result)
						check_result.add_partial_result(partial_result)
					return check_result
				result = func(*args, **kwargs)
				check_cache_store(check_id, result, cache_expiration, *args[1:], **kwargs)
				return result

		return wrapper
	return decorator

