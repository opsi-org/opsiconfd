# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
monitoring
"""

from datetime import datetime

import msgspec
from fastapi.responses import JSONResponse

from opsiconfd.application.jsonrpc import (
	JSONRPC20Request,
	JSONRPC20Response,
	RequestInfo,
	store_rpc_info,
)
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.redis import async_redis_client, decode_redis_result

from .utils import (
	State,
	generate_response,
	get_mem_allocated,
	get_request_avg,
	get_session_count,
	get_thread_count,
	get_workers,
)


async def check_opsi_webservice(
	cpu_thresholds: dict[str, int] | None = None, error_thresholds: dict[str, int] | None = None, perfdata: bool = True
) -> JSONResponse:
	state = State.OK
	message = []
	logger.debug("Generating Defaults for checkOpsiWebservice if not given")
	if not cpu_thresholds:
		cpu_thresholds = {"critical": 80, "warning": 60}
	if not error_thresholds:
		error_thresholds = {"critical": 20, "warning": 10}

	redis = await async_redis_client()

	try:
		for idx in range(100):
			await store_rpc_info(
				request=JSONRPC20Request(
					id=idx,
					method="accessControl_authenticated",
					info=RequestInfo(
						duration=0.00235,
						date=datetime.utcnow(),
						client="127.0.0.1/test-client",
					),
				),
				response=JSONRPC20Response(id=idx, result=True),
			)
		rpc_list = await redis.lrange(f"{config.redis_key('stats')}:rpcs", 0, 9999)
		error_count = 0
		for rpc in rpc_list:
			rpc = msgspec.msgpack.decode(rpc)
			if rpc["error"]:
				error_count += 1
		if error_count == 0:
			error_rate = 0.0
		else:
			rpc_num = len(rpc_list)
			error_rate = error_count / rpc_num * 100 if rpc_num > 0 else 0.0

		if error_rate > error_thresholds.get("critical", 0):
			message.append(f'RPC errors over {error_thresholds.get("critical")}%')
			state = State.CRITICAL
		elif error_rate > error_thresholds.get("warning", 0):
			message.append(f'RPC errors over {error_thresholds.get("warning")}%')
			state = State.WARNING

		workers = await get_workers(redis)
		cpu = 0.0
		for worker in workers:
			redis_result = decode_redis_result(
				await redis.execute_command(  # type: ignore[no-untyped-call]
					f"TS.GET {config.redis_key('stats')}:worker:avg_cpu_percent:{worker}:minute"
				)
			)
			cpu += float(redis_result[1]) if redis_result else 0.0
		cpu_avg = cpu / len(workers)
		cpu_avg = min(cpu_avg, 100.0)

		if cpu_avg > cpu_thresholds.get("critical", 0):
			state = State.CRITICAL
			message.append(f'CPU-Usage over {cpu_thresholds.get("critical")}%')
		elif cpu_avg > cpu_thresholds.get("warning", 0):
			if state != State.CRITICAL:
				state = State.WARNING
			message.append(f'CPU-Usage over {cpu_thresholds.get("warning")}%')

		if state == State.OK:
			message.append("Opsi Webservice has no Problem.")

		message_str = " ".join(message)

		if perfdata:
			performance = (
				f"requests={await get_request_avg(redis)};;;0; ",
				f"rpcs={len(rpc_list)};;;0; ",
				f"rpcerror={error_count};;;0; ",
				f"sessions={await get_session_count(redis)};;;0; ",
				f"threads={await get_thread_count(redis)};;;0; ",
				f"virtmem={await get_mem_allocated(redis)};;;0; ",
				f"cpu={cpu_avg};;;0;100 ",
			)
			return generate_response(state, message_str, "".join(performance))
		return generate_response(state, message_str)

	except Exception as err:
		logger.error(err, exc_info=True)
		state = State.UNKNOWN
		return generate_response(state, f"cannot check webservice state: '{str(err)}'.")
