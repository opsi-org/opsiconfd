# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
monitoring
"""

import msgpack
import orjson
from fastapi.responses import JSONResponse

from opsiconfd.logging import logger
from opsiconfd.utils import aredis_client, decode_redis_result

from .utils import (
	State, generate_response,
	get_workers, get_request_avg, get_session_count,
	get_thread_count, get_mem_allocated
)


async def check_opsi_webservice(cpu_thresholds=None, error_thresholds=None, perfdata=True) -> JSONResponse: # pylint: disable=too-many-branches, too-many-locals, too-many-statements
	state = State.OK
	message = []
	logger.debug("Generating Defaults for checkOpsiWebservice if not given")
	if not cpu_thresholds:
		cpu_thresholds = {"critical": 80, "warning": 60}
	if not error_thresholds:
		error_thresholds = {"critical": 20, "warning": 10}

	redis = await aredis_client()

	try:
		rpc_list = await redis.lrange("opsiconfd:stats:rpcs", 0, 9999)
		error_count = 0
		for rpc in rpc_list:
			try:
				rpc = msgpack.loads(rpc)
			except msgpack.exceptions.ExtraData:
				# Was json encoded before, can be removed in the future
				rpc = orjson.loads(rpc)  # pylint: disable=c-extension-no-member
			if rpc["error"]:
				error_count += 1
		if error_count == 0:
			error_rate = 0
		else:
			error_rate = error_count / len(rpc_list) * 100

		if error_rate > error_thresholds.get("critical"):
			message.append(f'RPC errors over {error_thresholds.get("critical")}%')
			state = State.CRITICAL
		elif error_rate >error_thresholds.get("warning"):
			message.append(f'RPC errors over {error_thresholds.get("warning")}%')
			state = State.WARNING

		workers = await get_workers(redis)
		cpu = 0
		for worker in workers:
			redis_result = decode_redis_result(
				await redis.execute_command(f"TS.GET opsiconfd:stats:worker:avg_cpu_percent:{worker}:minute")
			)
			if len(redis_result) == 0:
				redis_result = 0.0
			cpu += float(redis_result[1])

		cpu_avg = cpu/len(workers)

		if cpu_avg > cpu_thresholds.get("critical"):
			state = State.CRITICAL
			message.append(f'CPU-Usage over {cpu_thresholds.get("critical")}%')
		elif cpu_avg > cpu_thresholds.get("warning"):
			if state != State.CRITICAL:
				state = State.WARNING
			message.append(f'CPU-Usage over {cpu_thresholds.get("warning")}%')

		if state == State.OK:
			message.append("Opsi Webservice has no Problem.")

		message = " ".join(message)

		if perfdata:
			performance = [
				f"requests={await get_request_avg(redis)};;;0; ",
				f"rpcs={len(rpc_list)};;;0; ",
				f"rpcerror={error_count};;;0; ",
				f"sessions={await get_session_count(redis)};;;0; ",
				f"threads={await get_thread_count(redis)};;;0; ",
				f"virtmem={await get_mem_allocated(redis)};;;0; ",
				f"cpu={cpu_avg};;;0;100 "
			]
			return generate_response(state, message, "".join(performance))
		return generate_response(state, message)

	except Exception as err: # pylint: disable=broad-except
		state = State.UNKNOWN
		message = f"cannot check webservice state: '{str(err)}'."
		return generate_response(state, message)
