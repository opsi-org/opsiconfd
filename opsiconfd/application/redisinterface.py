# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
redisinterface
"""

import os
import traceback

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from ..logging import logger
from ..config import config
from ..worker import get_redis_client, sync_redis_client
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
	except Exception as err: # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		trace_back = traceback.format_exc()
		error = {"message": str(err), "class": err.__class__.__name__}
		error["details"] = str(trace_back)
		response = JSONResponse({"status": 500, "error": error, "data": {"result": None} })
	return response


@admin_interface_router.get("/redis-stats")
async def get_redis_stats():	# pylint: disable=too-many-locals
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
	except Exception as err: # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		response = JSONResponse({"status": 500, "error": { "message": "Error while reading redis data", "detail": str(err)}})
	return response

@admin_interface_router.get("/depot-cache")
def get_depot_cache():
	try:
		depots = _get_depots()
		response = JSONResponse({"status": 200, "error": None, "data": {"depots": list(depots)}})
	except Exception as err: # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		response = JSONResponse({"status": 500, "error": { "message": "Error while reading redis data", "detail": str(err)}})
	return response

def _get_depots():
	depots = {}
	with sync_redis_client() as redis:
		depots = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
	return depots

@admin_interface_router.get("/products")
def get_products(depot: str = None):
	try:
		data = []
		if depot:
			with sync_redis_client() as redis:
				products = decode_redis_result(redis.zrange(f"opsiconfd:jsonrpccache:{depot}:products", 0, -1))
				data.append({depot: products})
		else:
			with sync_redis_client() as redis:
				depots = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
				for depot in depots: # pylint: disable=redefined-argument-from-local
					products = decode_redis_result(redis.zrange(f"opsiconfd:jsonrpccache:{depot}:products", 0, -1))
					data.append({depot: products})
		response = JSONResponse({"status": 200, "error": None, "data": data})
	except Exception as err: # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		response = JSONResponse({"status": 500, "error": { "message": "Error while reading redis data", "detail": str(err)}})
	return response


@admin_interface_router.post("/clear-product-cache")
async def clear_product_cache(request: Request, response: Response):
	try:
		request_body = await request.json()
		depots = request_body.get("depots")
		if not depots:
			depots = _get_depots()
		with sync_redis_client() as redis:
			with redis.pipeline() as pipe:
				for depot in depots:
					pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products")
					pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm1")
					pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm2")
					pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:uptodate")
					pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm1:uptodate")
					pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm2:uptodate")
				data = pipe.execute()
		response = JSONResponse({"status": 200, "error": None, "data": data})
	except Exception as err: # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		response = JSONResponse({"status": 500, "error": { "message": "Error while reading redis data", "detail": str(err)}})
	return response
