"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""


import os
import datetime

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
	logger.notice("ADMIN INTERFACE")

	now = datetime.time()
	time = datetime.datetime.now() - datetime.timedelta(days=2)
	time = time.strftime("%m/%d/%Y, %H:%M:%S")
	logger.notice("TIME: %s",  time)
	
	redis_client = await get_redis_client()
	# keys = redis_client.scan_iter("opsiconfd:stats:worker:num_rpcs:*")
	# count = 0
	# logger.notice(keys)
	# async for key in keys:
	# 	logger.notice(key)
	# 	cmd = f"TS.RANGE {key.decode('utf8')} - + AGGREGATION sum 315400000000"
	# 	redis_result = await redis_client.execute_command(cmd)
	# 	count += int(redis_result[0][1].decode("utf8"))
	# 	logger.warning(count)
	count = await redis_client.get("opsiconfd:stats:rpc:count")
	context = {
		"request": request,
		"interface": get_backend_interface(),
		"count": count.decode("utf8"),
		"time": time
	}

	return templates.TemplateResponse("admininterface.html", context)

@admin_interface_router.post("/unblock-all")
async def unblock_all_clients(request: Request, response: Response):
	logger.notice("unblock_all_clients")
	redis_client = await get_redis_client()
	
	try:
		clients = []
		deleted_keys = []
		keys = redis_client.scan_iter("opsiconfd:stats:client:failed_auth:*")
		async for key in keys:
			deleted_keys.append(key.decode("utf8"))
			if key.decode("utf8").split(":")[-1] not in clients:
				clients.append(key.decode("utf8").split(":")[-1])
			logger.debug("redis key to delete: %s", key)
			await redis_client.delete(key)

		keys = redis_client.scan_iter("opsiconfd:stats:client:blocked:*")		
		async for key in keys:
			logger.debug("redis key to delete: %s", key)
			deleted_keys.append(key.decode("utf8"))
			if key.decode("utf8").split(":")[-1] not in clients:
				clients.append(key.decode("utf8").split(":")[-1])
			await redis_client.delete(key)

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
		async for key in keys:
			logger.warning(key)
			logger.notice(key.decode("utf8").split(":")[-1])
			logger.warning(sessions)
			sessions.append(key.decode("utf8").split(":")[-1])
			deleted_keys.append(key.decode("utf8"))
			await redis_client.delete(key)
			
		logger.notice(sessions)
		logger.notice(deleted_keys)
		response = JSONResponse({"status": 200, "error": None, "data": {"client": client_addr, "sessions": sessions, "redis-keys": deleted_keys}})
	except Exception as e:
		logger.error("Error while removing redis session keys: %s", e)
		response = JSONResponse({"status": 500, "error": { "message": "Error while removing redis client keys", "detail": str(e)}})
	return response
