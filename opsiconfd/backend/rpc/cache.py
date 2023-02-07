# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.cache
"""

from collections import defaultdict
from hashlib import sha256
from typing import Any

from msgspec.msgpack import decode, encode

from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.redis import delete_recursively, redis_client

CACHE_EXPIRATION = 24 * 3600  # In seconds


def redis_key_for_params(cache_name: str, *args: Any, **kwargs: Any) -> str:
	hash_base = encode(args) + encode(dict(sorted(kwargs.items())))
	param_hash = sha256(hash_base).hexdigest()
	return f"{config.redis_key('rpccache')}:{cache_name}:{param_hash}"


def rpc_cache_store(cache_name: str, result: Any, *args: Any, **kwargs: Any) -> None:
	redis_key = redis_key_for_params(cache_name, *args, **kwargs)
	with redis_client() as redis:
		logger.debug("RPC cache store: %s", redis_key)
		redis.set(redis_key, encode(result), ex=CACHE_EXPIRATION)


def rpc_cache_load(cache_name: str, *args: Any, **kwargs: Any) -> Any:
	redis_key = redis_key_for_params(cache_name, *args, **kwargs)
	with redis_client() as redis:
		msgpack_data = redis.get(redis_key)
		if msgpack_data:
			logger.debug("RPC cache hit: %s", redis_key)
			return decode(msgpack_data)
	logger.debug("RPC cache miss: %s", redis_key)
	return None


def rpc_cache_clear(cache_name: str | None = None) -> Any:
	redis_key = config.redis_key("rpccache")
	if cache_name:
		redis_key = f"{redis_key}:{cache_name}"
	delete_recursively(redis_key)


def rpc_cache_info() -> dict[str, int]:
	info: dict[str, int] = defaultdict(int)
	prefix = f"{config.redis_key('rpccache')}:"
	with redis_client() as redis:
		for key in redis.scan_iter(f"{prefix}*"):
			rel = key.decode("utf-8").removeprefix(prefix)
			if ":" in rel:
				cache_name, _ = rel.split(":", 1)
				info[cache_name] += 1
	return info
