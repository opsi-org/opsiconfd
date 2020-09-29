"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""
import orjson

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from OPSI.Types import forceProductIdList

from opsiconfd.logging import logger
from opsiconfd.worker import get_redis_client
from opsiconfd.utils import decode_redis_result

from .utils import State, generateResponse 
from .utils import get_workers, get_request_avg, get_session_count, get_thread_count, get_mem_allocated


async def check_opsi_webservice(cpu_thresholds=None, error_thresholds=None, perfdata=True):
	logger.devel("checkOpsiWebservice")
	state = State.OK
	message = []
	logger.debug("Generating Defaults for checkOpsiWebservice if not given")
	if not cpu_thresholds:
		cpu_thresholds = {"critical": 80, "warning": 60}
	if not error_thresholds:
		error_thresholds = {"critical": 20, "warning": 10}

	redis_client = await get_redis_client()

	try:
		rpc_list = decode_redis_result(await redis_client.lrange("opsiconfd:stats:rpcs", 0, 9999))
		logger.devel("RPC List: %s", rpc_list)
		error_count = 0
		for rpc in rpc_list:
			rpc = orjson.loads(rpc)
			if rpc["error"]:
				error_count += 1
				logger.devel(rpc)
		if error_count == 0:
			error_rate = 0
		else:
			error_rate = error_count / len(rpc_list) * 100
		logger.devel(error_rate)

		if error_rate > error_thresholds.get("critical"):
			message.append(f'RPC errors over {error_thresholds.get("critical")}%')
			state = State.CRITICAL
		elif error_rate >error_thresholds.get("warning"):
			message.append(f'RPC errors over {error_thresholds.get("warning")}%')
			state = State.WARNING

		workers = await get_workers(redis_client)
		
		logger.devel("workers: %s", workers)
		cpu = 0
		for worker in workers:
			redis_result = decode_redis_result(await redis_client.execute_command(f"TS.GET opsiconfd:stats:worker:avg_cpu_percent:{worker}:minute"))
			logger.devel("redis_result %s", redis_result)
			if len(redis_result) == 0:
				redis_result = 0.0
			cpu += float(redis_result[1])

		cpu_avg = cpu/len(workers)*100
		logger.devel("cpu_avg: %s", cpu_avg)


		if cpu_avg > cpu_thresholds.get("critical"):
			state = State.CRITICAL
			message.append(f'CPU-Usage over {cpu_thresholds.get("critical")}%')
		elif cpu_avg > cpu_thresholds.get("warning"):
			if not state == State.CRITICAL:
				state = State.WARNING
			message.append(f'CPU-Usage over {cpu_thresholds.get("warning")}%')

		if state == State.OK:
			message.append("Opsi Webservice has no Problem :)")

		message = " ".join(message)
		
		if perfdata:
			performance = [
				f"requests={await get_request_avg(redis_client)};;;0; ",
				f"rpcs={len(rpc_list)};;;0; ",
				f"rpcerror={error_count};;;0; ",
				f"sessions={await get_session_count(redis_client)};;;0; ",
				f"threads={await get_thread_count(redis_client)};;;0; ",
				f"virtmem={await get_mem_allocated(redis_client)};;;0; ",
				f"cpu={cpu_avg};;;0;100 " 
			]

			return generateResponse(state, message, "".join(performance))
		else:
			return generateResponse(state, message)

	except Exception as e:
		state = State.UNKNOWN
		message = f"cannot check webservice state: '{str(e)}'."
		return generateResponse(state, message)
