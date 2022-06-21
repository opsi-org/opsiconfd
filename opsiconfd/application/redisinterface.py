# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
redisinterface
"""

import traceback

from aioredis.exceptions import ResponseError
from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from opsiconfd import rest

from .. import contextvar_client_session
from ..logging import logger
from ..rest import OpsiApiException, rest_api
from ..utils import (
	async_get_redis_info,
	async_redis_client,
	decode_redis_result,
	redis_client,
)

redis_interface_router = APIRouter()


def redis_interface_setup(app):
	app.include_router(redis_interface_router, prefix="/redis-interface")


@redis_interface_router.post("")
@redis_interface_router.post("/")
@rest_api(default_error_status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
async def redis_command(request: Request):
	redis = await async_redis_client()
	request_body = await request.json()
	redis_cmd = request_body.get("cmd")
	redis_result = await redis.execute_command(redis_cmd)
	return {"data": {"result": decode_redis_result(redis_result)}}


@redis_interface_router.get("/redis-stats")
@rest_api
async def get_redis_stats():  # pylint: disable=too-many-locals
	redis = await async_redis_client()
	try:
		redis_info = await async_get_redis_info(redis)
		return {"data": redis_info}
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		raise OpsiApiException(error=err, message="Error while reading redis data") from err


@redis_interface_router.get("/depot-cache")
@rest_api
def get_depot_cache():
	try:
		depots = _get_depots()
		return {"data": {"depots": list(depots)}}
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		raise OpsiApiException(error=err, message="Error while reading redis data") from err


def _get_depots():
	depots = {}
	with redis_client() as redis:
		depots = decode_redis_result(redis.smembers("opsiconfd:jsonrpccache:depots"))
	return depots


@redis_interface_router.get("/products")
@rest_api
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
		return {"data": data}
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		raise OpsiApiException(error=err, message="Error while reading redis data") from err


@redis_interface_router.post("/clear-product-cache")
@rest_api
async def clear_product_cache(request: Request):
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
		return {"data": data}
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while reading redis data: %s", err)
		raise OpsiApiException(error=err, message="Error while reading redis data") from err
