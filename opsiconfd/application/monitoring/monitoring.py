"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

import orjson
import datetime

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse


from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.backend import get_client_backend, get_backend

from .utils import State
from .check_client_status import check_client_status
from .check_short_product_status import check_short_product_status
from .check_product_status import check_product_status

monitoring_router = APIRouter()


def monitoring_setup(app):
	app.include_router(monitoring_router, prefix="/monitoring")



@monitoring_router.post("/?")
async def monitoring(request: Request):

	backend = get_backend()

	logger.devel("Request: %s", await request.json())
	request_data = await request.json()
	
	try:
		task = request_data["task"]
	except KeyError :
		logger.error("No task set, nothing to do")
		response = JSONResponse({"state":  State.UNKNOWN, "message": "No task set, nothing to do"})

	params = request_data.get("param", {})
	logger.devel("task: %s", task)
	try:
		if task == "checkClientStatus":
			response = check_client_status(
				backend=backend,
				clientId=params.get("clientId", None),
				excludeProductList=params.get("exclude", None)
			)
		if task == "checkShortProductStatus":
			response = check_short_product_status(
				backend=backend,
				productId=params.get("productId", None),
				thresholds=params.get("thresholds", {})

			)
		if task == "checkProductStatus":
			response =  check_product_status(
				backend=backend,
				productIds=params.get("productIds", []), 
				productGroups=params.get("productGroups", []), 
				hostGroupIds=params.get("hostGroupIds", []), 
				depotIds=params.get("depotIds", []), 
				exclude=params.get("exclude", []),
				verbose=params.get("verbose", False)
			)
		else:
			response = JSONResponse({"state": State.UNKNOWN})
	except Exception as e:
		logger.error(e)
		response = JSONResponse({"state": State.UNKNOWN, "message": str(e)})


	logger.devel(response)
	return response





