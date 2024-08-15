# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.check.cache
"""

from functools import wraps
from typing import Any, Callable

from msgspec.msgpack import decode, encode

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



def clear_check_cache(
	func: Callable | None = None,
	/,
	*,
	check_id: str | None = None,
) -> Callable:
	def decorator(func: Callable) -> Callable:
		@wraps(func)
		def wrapper(*args: Any, **kwargs: Any) -> Any:
			check_cache_clear(check_id)
			return func(*args, **kwargs)
		return wrapper
	return decorator


