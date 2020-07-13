"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""


import os

from fastapi import APIRouter, Request, Response
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
	context = {
		"request": request,
		"interface": get_backend_interface()
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

		response = JSONResponse({"success": True, "clients": clients, "redis-keys": deleted_keys})
	except Exception as e:
		logger.error("Error while removing redis client keys: %s", e)
		response = JSONResponse({'success': False, 'error': str(e)})

	return response


@admin_interface_router.post("/unblock-client")
async def unblock_client(request: Request):
	try:
		request_body = await request.json()
		client_addr = request_body.get("client_addr")
		logger.debug("unblock client addr: %s ", client_addr)
		redis_client = await get_redis_client()
		await redis_client.delete(f"opsiconfd:stats:client:failed_auth:{client_addr}")
		await redis_client.delete(f"opsiconfd:stats:client:blocked:{client_addr}")

		response = JSONResponse({"success": True, "client": client_addr})
	except Exception as e:
		logger.error("Error while removing redis client keys: %s", e)
		response = JSONResponse({'success': False, 'error': str(e)})

	return response


@admin_interface_router.post("/delete-client-sessions")
async def delete_client_sessions(request: Request):
	try:
		request_body = await request.json()
		client_addr = request_body.get("client_addr")
		redis_client = await get_redis_client()
		keys = redis_client.scan_iter(f"{OPSISession}:{client_addr}:*")
		async for key in keys:
			await redis_client.delete(key)
		
		response = JSONResponse({"success": True, "client": client_addr})
	except Exception as e:
		logger.error("Error while removing redis client keys: %s", e)
		response = JSONResponse({'success': False, 'error': str(e)})

	return response
