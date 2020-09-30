"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

import os
import datetime
import traceback

from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..session import OPSISession
from ..logging import logger
from ..config import config
from ..backend import get_client_backend, get_backend_interface
from ..worker import get_redis_client
from ..utils import decode_redis_result

admin_interface_router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(config.static_dir, "templates"))

def redis_interface_setup(app):
	app.include_router(admin_interface_router, prefix="/redis-interface")


@admin_interface_router.post("/?")
async def redis_command(request: Request, response: Response):
	redis_client = await get_redis_client()
	try:
		request_body = await request.json()
		redis_cmd = request_body.get("cmd")
		redis_result = await redis_client.execute_command(redis_cmd)
				
		response = JSONResponse({
			"status": 200,
			"error": None,
			"data": {"result": decode_redis_result(redis_result)}
		})
	except Exception as e:
		logger.error(e, exc_info=True)
		tb = traceback.format_exc()
		error = {"message": str(e), "class": e.__class__.__name__}
		if True:
			error["details"] = str(tb)
		response = JSONResponse({"status": 500, "error": error, "data": {"result": None} })
	return response


@admin_interface_router.get("/redis-stats")
async def get_redis_stats():
	redis_client = await get_redis_client()
	try: 	
		stats_keys = []
		sessions_keys = []
		log_keys = []
		rpc_keys = []
		misc_keys = []
		redis_keys = redis_client.scan_iter("opsiconfd:*")
		
		async for key in redis_keys:
			key = key.decode("utf8")
			if key.startswith("opsiconfd:stats:rpc") or key.startswith("opsiconfd:stats:num_rpc"):
				rpc_keys.append(key)
			elif key.startswith("opsiconfd:stats"):
				stats_keys.append(key)
			elif key.startswith("opsiconfd:sessions"):
				sessions_keys.append(key)
			elif key.startswith("opsiconfd:log"):
				log_keys.append(key)
			else:
				misc_keys.append(key)
		
		stats_memory = 0
		for key in stats_keys:
			stats_memory += await redis_client.execute_command(f"MEMORY USAGE {key}")
			
		sessions_memory = 0
		for key in sessions_keys:
			sessions_memory += await redis_client.execute_command(f"MEMORY USAGE {key}")

		logs_memory = 0
		for key in log_keys:
			logs_memory += await redis_client.execute_command(f"MEMORY USAGE {key}")

		rpc_memory = 0
		for key in rpc_keys:
			rpc_memory += await redis_client.execute_command(f"MEMORY USAGE {key}")
		
		misc_memory = 0
		for key in misc_keys:
			misc_memory += await redis_client.execute_command(f"MEMORY USAGE {key}")
			
		redis_info = decode_redis_result(await redis_client.execute_command("INFO"))
		redis_info["key_info"] = {
			"stats":{
				"count":len(stats_keys),
				"memory": stats_memory
			},
			"sessions":{
				"count":len(sessions_keys),
				"memory": sessions_memory
			},
			"logs":{
				"count":len(log_keys),
				"memory": logs_memory
			},
			"rpc":{
				"count":len(rpc_keys),
				"memory": rpc_memory
			},
			"misc":{
				"count":len(misc_keys),
				"memory": misc_memory
			}
		}
		response = JSONResponse({"status": 200, "error": None, "data": redis_info})
	except Exception as e:
		logger.error("Error while reading redis data: %s", e)
		response = JSONResponse({"status": 500, "error": { "message": "Error while reading redis data", "detail": str(e)}})
	return response