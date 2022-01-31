# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
redisinterface
"""

import traceback

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from ..logging import logger
from ..utils import decode_redis_result, async_get_redis_info, redis_client, async_redis_client

redis_interface_router = APIRouter()


def redis_interface_setup(app):
	app.include_router(redis_interface_router, prefix="/redis-interface")


@redis_interface_router.post("")
@redis_interface_router.post("/")
async def redis_command(request: Request, response: Response):
	redis = await async_redis_client()
	try:
		request_body = await request.json()
		redis_cmd = request_body.get("cmd")
		redis_result = await redis.execute_command(redis_cmd)

		response = JSONResponse({"status": 200, "error": None, "data": {"result": decode_redis_result(redis_result)}})
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		trace_back = traceback.format_exc()
		error = {"message": str(err), "class": err.__class__.__name__}
		error["details"] = str(trace_back)
		response = JSONResponse({"status": 500, "error": error, "data": {"result": None}})
	return response


@redis_interface_router.get("/redis-stats")
async def get_redis_stats():  # pylint: disable=too-many-locals
	redis = await async_redis_client()
	try:
		redis_info = await async_get_redis_info(redis)
		response = JSONResponse({"status": 200, "error": None, "data": redis_info})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while reading redis data", "detail": str(err)}})
	return response


@redis_interface_router.get("/depot-cache")
def get_depot_cache():
	try:
		depots = _get_depots()
		response = JSONResponse({"status": 200, "error": None, "data": {"depots": list(depots)}})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while reading redis data", "detail": str(err)}})
	return response


def _get_depots():
	depots = {}
	with redis_client() as redis:
		depots = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
	return depots


@redis_interface_router.get("/products")
def get_products(depot_id: str = None):
	try:
		data = {}
		with redis_client() as redis:
			depot_ids = []
			if depot_id:
				depot_ids.append(depot_id)
			else:
				depot_ids = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
			for dep_id in depot_ids:
				products = decode_redis_result(redis.zrange(f"opsiconfd:jsonrpccache:{dep_id}:products", 0, -1))
				data[dep_id] = products
		return JSONResponse({"status": 200, "error": None, "data": data})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		return JSONResponse({"status": 500, "error": {"message": "Error while reading redis data", "detail": str(err)}})


@redis_interface_router.post("/clear-product-cache")
async def clear_product_cache(request: Request, response: Response):
	try:
		request_body = await request.json()
		depots = request_body.get("depots")
		if not depots:
			depots = _get_depots()
		redis = await async_redis_client()
		async with redis.pipeline() as pipe:
			for depot in depots:
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm1")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm2")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:uptodate")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm1:uptodate")
				pipe.delete(f"opsiconfd:jsonrpccache:{depot}:products:algorithm2:uptodate")
			data = await pipe.execute()
		response = JSONResponse({"status": 200, "error": None, "data": data})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while reading redis data", "detail": str(err)}})
	return response
