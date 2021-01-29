"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""
import re

from fastapi.responses import JSONResponse

from opsiconfd.utils import decode_redis_result

ERRORCODE_PATTERN = re.compile('\[Errno\s(\d*)\]\sCommand\s(\'.*\')\sfailed\s\(\d*\)\:\s(.*)') # pylint: disable=anomalous-backslash-in-string

class State: # pylint: disable=too-few-public-methods
	OK = 0
	WARNING = 1
	CRITICAL = 2
	UNKNOWN = 3

	_stateText = ["OK", "WARNING", "CRITICAL", "UNKNOWN"]

	@classmethod
	def text(cls, state):
		return cls._stateText[state]

def generate_response(state: State, message: str, perfdata=None) -> JSONResponse:
	if perfdata:
		message = f"{State.text(state)}: {message} | {perfdata}"
	else:
		message = f"{State.text(state)}: {message}"
	return JSONResponse({"state": state, "message": message})

def remove_percent(string):
	if string.endswith("%"):
		return string[:-1]
	return string

async def get_workers(redis_client) -> list:
	worker_registry = redis_client.scan_iter("opsiconfd:worker_registry:*")
	workers = []
	async for key in worker_registry:
		workers.append(f"{key.decode('utf8').split(':')[-2]}:{key.decode('utf8').split(':')[-1]}")
	return workers

async def get_request_avg(redis_client):
	workers = await get_workers(redis_client)
	requests = 0.0
	for worker in workers:
		redis_result = decode_redis_result(
			await redis_client.execute_command(
				f"TS.GET opsiconfd:stats:worker:sum_http_request_number:{worker}:minute"
			)
		)
		if len(redis_result) == 0:
			redis_result = 0
		requests += float(redis_result[1])
	return requests / len(workers) * 100

async def get_session_count(redis_client):
	count = 0
	session_keys = redis_client.scan_iter("opsiconfd:sessions:*")
	async for _session in session_keys:
		count += 1
	return count

async def get_thread_count(redis_client):
	workers = await get_workers(redis_client)
	threads = 0
	for worker in workers:
		redis_result = decode_redis_result(
			await redis_client.execute_command(
				f"TS.GET opsiconfd:stats:worker:avg_thread_number:{worker}:minute"
			)
		)
		if len(redis_result) == 0:
			redis_result = 0
		threads += float(redis_result[1])
	return threads

async def get_mem_allocated(redis_client):
	workers = await get_workers(redis_client)
	mem_allocated = 0
	for worker in workers:
		redis_result = decode_redis_result(
			await redis_client.execute_command(
				f"TS.GET opsiconfd:stats:worker:avg_thread_number:{worker}:minute"
			)
		)
		if len(redis_result) == 0:
			redis_result = 0
		mem_allocated += float(redis_result[1])
	return mem_allocated
