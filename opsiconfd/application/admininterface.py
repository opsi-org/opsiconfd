"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

import os
import datetime
from operator import itemgetter

from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..session import OPSISession
from ..logging import logger
from ..config import config
from ..backend import get_client_backend, get_backend_interface
from ..worker import get_redis_client

admin_interface_router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(config.static_dir, "templates"))


def admin_interface_setup(app):
	app.include_router(admin_interface_router, prefix="/admin")


@admin_interface_router.get("/?")
async def admin_interface_index(request: Request):

	time = datetime.datetime.now() - datetime.timedelta(days=2)
	date_first_rpc = time.strftime("%m/%d/%Y, %H:%M:%S")

	rpc_count = await _get_rpc_count()
	
	context = {
		"request": request,
		"interface": get_backend_interface(),
		"rpc_count": rpc_count,
		"date_first_rpc": date_first_rpc,
	}
	return templates.TemplateResponse("admininterface.html", context)


@admin_interface_router.post("/unblock-all")
async def unblock_all_clients(request: Request, response: Response):
	redis_client = await get_redis_client()
	
	try:
		clients = []
		deleted_keys = []
		keys = redis_client.scan_iter("opsiconfd:stats:client:failed_auth:*")
		async with await redis_client.pipeline(transaction=False) as pipe:
			async for key in keys:
				deleted_keys.append(key.decode("utf8"))
				if key.decode("utf8").split(":")[-1] not in clients:
					clients.append(key.decode("utf8").split(":")[-1])
				logger.debug("redis key to delete: %s", key)
				await pipe.delete(key)

			keys = redis_client.scan_iter("opsiconfd:stats:client:blocked:*")		
			async for key in keys:
				logger.debug("redis key to delete: %s", key)
				deleted_keys.append(key.decode("utf8"))
				if key.decode("utf8").split(":")[-1] not in clients:
					clients.append(key.decode("utf8").split(":")[-1])
				await pipe.delete(key)
			redis_result = await pipe.execute()

		response = JSONResponse({"status": 200, "error": None, "data": {"clients": clients, "redis-keys": deleted_keys}})
	except Exception as e:
		logger.error("Error while removing redis client keys: %s", e)
		response = JSONResponse({"status": 500, "error": { "message": "Error while removing redis client keys", "detail": str(e)}})
	return response


@admin_interface_router.post("/unblock-client")
async def unblock_client(request: Request):
	try:
		request_body = await request.json()
		client_addr = request_body.get("client_addr")
		
		logger.debug("unblock client addr: %s ", client_addr)
		redis_client = await get_redis_client()
		deleted_keys = []
		redis_code = await redis_client.delete(f"opsiconfd:stats:client:failed_auth:{client_addr}")
		if redis_code == 1:
			deleted_keys.append(f"opsiconfd:stats:client:failed_auth:{client_addr}")
		redis_code = await redis_client.delete(f"opsiconfd:stats:client:blocked:{client_addr}")
		if redis_code == 1:
			deleted_keys.append(f"opsiconfd:stats:client:blocked:{client_addr}")

		response = JSONResponse({"status": 200, "error": None, "data": {"client": client_addr, "redis-keys": deleted_keys}})
	except Exception as e:
		logger.error("Error while removing redis client keys: %s", e)
		response = JSONResponse({"status": 500, "error": { "message": "Error while removing redis client keys", "detail": str(e)}})
	return response


@admin_interface_router.post("/delete-client-sessions")
async def delete_client_sessions(request: Request):
	try:
		request_body = await request.json()
		client_addr = request_body.get("client_addr")
		redis_client = await get_redis_client()
		keys = redis_client.scan_iter(f"{OPSISession.redis_key_prefix}:{client_addr}:*")
		sessions = []
		deleted_keys = []
		async with await redis_client.pipeline(transaction=False) as pipe:
			async for key in keys:
				sessions.append(key.decode("utf8").split(":")[-1])
				deleted_keys.append(key.decode("utf8"))
				await pipe.delete(key)
			redis_result = await pipe.execute()

		response = JSONResponse({"status": 200, "error": None, "data": {"client": client_addr, "sessions": sessions, "redis-keys": deleted_keys}})
	except Exception as e:
		logger.error("Error while removing redis session keys: %s", e)
		response = JSONResponse({"status": 500, "error": { "message": "Error while removing redis client keys", "detail": str(e)}})
	return response


@admin_interface_router.get("/rpc-list")
async def get_rpc_list(limit: int = 250) -> list:

	redis_client = await get_redis_client()
	redis_keys = redis_client.scan_iter(f"opsiconfd:stats:rpc:*")

	keys = []
	async for key in redis_keys:
		keys.append(key)
	keys = sorted(keys, key=lambda key: get_num_from_key(key)) 
	keys = keys[-limit:]

	rpc_list = []
	for key in keys:
		async with await redis_client.pipeline(transaction=False) as pipe:
			await pipe.hget(key, "num_params")
			await pipe.hget(key, "error")
			await pipe.hget(key, "num_results")
			await pipe.hget(key, "duration")
			await pipe.hget(key, "date")
			await pipe.hget(key, "client")
			redis_result = await pipe.execute()

		num_params = redis_result[0].decode("utf8")
		error = (redis_result[1].decode("utf8") == "True")
		num_results = redis_result[2].decode("utf8")
		duration = "{:.3f}".format(float(redis_result[3].decode("utf8")))
		if redis_result[4]:
			date = redis_result[4].decode("utf8")
		else:
			date = datetime.date(2020,1,1).strftime('%Y-%m-%dT%H:%M:%SZ')
		if redis_result[5]:
			client = redis_result[5].decode("utf8")
		else:
			client = "0.0.0.0"
		method_name = key.decode("utf8").split(":")[-1]			
		
		rpc = {"rpc_num": int(key.decode("utf8").split(":")[-2]), "method": method_name, "params": num_params, "results": num_results, "date": date, "client": client, "error": error, "duration": duration}
		rpc_list.append(rpc)
	rpc_list = sorted(rpc_list, key=itemgetter('rpc_num')) 
	return rpc_list


@admin_interface_router.get("/rpc-count")
async def get_rpc_count(): 
	count = await _get_rpc_count()
	time = datetime.datetime.now() - datetime.timedelta(days=2)
	date_first_rpc = time.strftime('%Y-%m-%dT%H:%M:%SZ')

	response = JSONResponse({"rpc_count": count, "date_first_rpc": date_first_rpc})
	return response

async def _get_rpc_count() -> int: 
	redis_client = await get_redis_client()

	count = await redis_client.get("opsiconfd:stats:num_rpcs")
	if count:
		count = int(count.decode("utf8"))
	else:
		count = 0
	return count

@admin_interface_router.get("/blocked-clients")
async def get_blocked_clients() -> list:
	redis_client = await get_redis_client()
	redis_keys = redis_client.scan_iter("opsiconfd:stats:client:blocked:*")

	blocked_clients = []
	async for key in redis_keys:
		logger.debug("redis key to delete: %s", key)
		blocked_clients.append(key.decode("utf8").split(":")[-1])
	return blocked_clients

def get_num_from_key(key):
	num = key.decode("utf8").split(":")[-2]
	return int(num)