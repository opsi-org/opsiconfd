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
		
		if type(redis_result) == list:
			result = []
			for value in redis_result:
				result.append(value.decode("utf8"))
		else:
			result = redis_result.decode("utf8")
		
		response = JSONResponse({"status": 200, "error": None, "data": {"result": result}})
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
		misc_keys = []

		redis_keys = redis_client.scan_iter("opsiconfd:*")
		
		async for key in redis_keys:
			key = key.decode("utf8")
			if key.startswith("opsiconfd:stats"):
				stats_keys.append(key)
			elif key.startswith("opsiconfd:sessions"):
				sessions_keys.append(key)
			elif key.startswith("opsiconfd:log"):
				log_keys.append(key)
			else:
				logger.devel(key)
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
		
		misc_memory = 0
		for key in misc_keys:
			misc_memory += await redis_client.execute_command(f"MEMORY USAGE {key}")
		
		# keys = {
		# 	"stats":{
		# 		"count":len(stats_keys),
		# 		"memory": stats_memory
		# 	},
		# 	"sessions":{
		# 		"count":len(sessions_keys),
		# 		"memory": sessions_memory
		# 	},
		# 	"logs":{
		# 		"count":len(log_keys),
		# 		"memory": logs_memory
		# 	},
		# 	"misc":{
		# 		"count":len(misc_keys),
		# 		"memory": misc_memory
		# 	}
		# }
		#.format(len(stats_keys), len(sessions_keys),len(log_keys),len(misc_keys))
		# logger.devel(keys)

		# memory_stats = await redis_client.execute_command(f"MEMORY STATS")
		# total_memory = 0
		# key_count = 0
		# for idx, val in enumerate(memory_stats):
		# 	if type(val) == bytes:
		# 		val = val.decode("utf8")
		# 		if "total.allocated" in val:
		# 			total_memory = memory_stats[idx+1]
		# 		if "keys.count" in val:
		# 			key_count = memory_stats[idx+1]

		# logger.devel(memory_stats)
		

		redis_info =  await redis_client.execute_command(f"INFO")
		logger.devel(redis_info.get("module"))
		logger.devel(redis_info.get("redis_version"))

		

		redis_version = redis_info.get("redis_version")
		connected_clients = redis_info.get("connected_clients")
		used_memory_human = redis_info.get("used_memory_human")
		total_memory = redis_info.get("used_memory")
		total_keys_info = redis_info.get("db0")

		redis_module =  await redis_client.execute_command(f"MODULE LIST")
		logger.devel(redis_module)

		modules = []
		for module in redis_module:
			modules.append({"name": module[1].decode("utf8"), "ver": module[3]})

		
		
		redis_data = {
			"redis_version": redis_version, 
			"modules": modules,
			"clients": connected_clients, 
			"memory_human": used_memory_human, 
			"memory": total_memory,
			"keys": {
				"count": total_keys_info.get("keys"),
				"expires": total_keys_info.get("expires"),
				"avg_ttl": total_keys_info.get("avg_ttl"),
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
				"misc":{
					"count":len(misc_keys),
					"memory": misc_memory
				}
			}
		}  
		logger.devel(redis_data)

		

		response = JSONResponse({"status": 200, "error": None, "data": redis_data})
		logger.devel(response.__dict__)
	except Exception as e:
		logger.error("Error while reading redis data: %s", e)
		response = JSONResponse({"status": 500, "error": { "message": "Error while reading redis data", "detail": str(e)}})
	return response