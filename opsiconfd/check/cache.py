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

from opsiconfd.logging import logger
from opsiconfd.redis import delete_recursively


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
