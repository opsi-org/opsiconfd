# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
monitoring
"""

import re
from typing import Any

from fastapi.responses import JSONResponse
from redis.asyncio import StrictRedis

from opsiconfd.config import config
from opsiconfd.redis import decode_redis_result

ERRORCODE_PATTERN = re.compile(r"\[Errno\s(\d*)\]\sCommand\s(\'.*\')\sfailed\s\(\d*\)\:\s(.*)")


class State:
	OK = 0
	WARNING = 1
	CRITICAL = 2
	UNKNOWN = 3

	_stateText = ("OK", "WARNING", "CRITICAL", "UNKNOWN")

	@classmethod
	def text(cls, state: int) -> str:
		return cls._stateText[state]


def generate_response(state: int, message: str, perfdata: Any = None) -> JSONResponse:
	if perfdata:
		message = f"{State.text(state)}: {message} | {perfdata}"
	else:
		message = f"{State.text(state)}: {message}"
	return JSONResponse({"state": state, "message": message})


def remove_percent(string: str) -> str:
	if string.endswith("%"):
		return string[:-1]
	return string


async def get_workers(redis: StrictRedis) -> list:
	worker_registry = redis.scan_iter(f"{config.redis_key('state')}:workers:*")
	workers = []
	async for key in worker_registry:
		workers.append(f"{key.decode('utf8').split(':')[-2]}:{key.decode('utf8').split(':')[-1]}")
	return workers


async def get_request_avg(redis: StrictRedis) -> float:
	workers = await get_workers(redis)
	requests = 0.0
	for worker in workers:
		redis_result = decode_redis_result(
			await redis.execute_command(  # type: ignore[no-untyped-call]
				f"TS.GET {config.redis_key('stats')}:worker:sum_http_request_number:{worker}:minute"
			)
		)
		if len(redis_result) == 0:
			redis_result = 0
		requests += float(redis_result[1])
	return requests / len(workers) * 100


async def get_session_count(redis: StrictRedis) -> int:
	count = 0
	session_keys = redis.scan_iter(f"{config.redis_key('session')}:*")
	async for _session in session_keys:
		count += 1
	return count


async def get_thread_count(redis: StrictRedis) -> float:
	workers = await get_workers(redis)
	threads = 0.0
	for worker in workers:
		redis_result = decode_redis_result(
			await redis.execute_command(  # type: ignore[no-untyped-call]
				f"TS.GET {config.redis_key('stats')}:worker:avg_thread_number:{worker}:minute"
			)
		)
		if len(redis_result) == 0:
			redis_result = 0
		threads += float(redis_result[1])
	return threads


async def get_mem_allocated(redis: StrictRedis) -> float:
	workers = await get_workers(redis)
	mem_allocated = 0.0
	for worker in workers:
		redis_result = decode_redis_result(
			await redis.execute_command(  # type: ignore[no-untyped-call]
				f"TS.GET {config.redis_key('stats')}:worker:avg_thread_number:{worker}:minute"
			)
		)
		if len(redis_result) == 0:
			redis_result = 0
		mem_allocated += float(redis_result[1])
	return mem_allocated
