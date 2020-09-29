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
from .check_depot_sync_status import check_depot_sync_status
from .check_plugin_on_client import check_plugin_on_client
from .check_opsi_webservice import check_opsi_webservice
from .check_locked_products import check_locked_products

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
		elif task == "checkShortProductStatus":
			response = check_short_product_status(
				backend=backend,
				productId=params.get("productId", None),
				thresholds=params.get("thresholds", {})

			)
		elif task == "checkProductStatus":
			response =  check_product_status(
				backend=backend,
				productIds=params.get("productIds", []), 
				productGroups=params.get("productGroups", []), 
				hostGroupIds=params.get("hostGroupIds", []), 
				depotIds=params.get("depotIds", []), 
				exclude=params.get("exclude", []),
				verbose=params.get("verbose", False)
			)
		elif task == "checkDepotSyncStatus":
			response = check_depot_sync_status(
				backend=backend,
				depotIds=params.get("depotIds", []), 
				productIds=params.get("productIds", []), 
				exclude=params.get("exclude", []), 
				strict=params.get("strict", False), 
				verbose=params.get("verbose", False)
			)
		elif task == "checkPluginOnClient":
			response = check_plugin_on_client(
				backend=backend,
				hostId=params.get("clientId", []), 
				command=params.get("plugin", ""), 
				timeout=params.get("timeout", 30),
				waitForEnding=params.get("waitForEnding", True),
				captureStderr=params.get("captureStdErr", True),
				statebefore=params.get("state", None),
				output=params.get("output", None), 
				encoding=params.get("encoding", None),
			)
		elif task == "checkProductLocks":
			response = check_locked_products(
				backend=backend,
				depotIds=params.get("depotIds", []),
				productIds=params.get("productIds", []),
			)
		elif task == "checkOpsiWebservice":
			
			response = await check_opsi_webservice(
				cpu_thresholds=params.get("cpu", {}),
				error_thresholds=params.get("errors", {}),
				perfdata=params.get("perfdata", True)
			)
		else:
			response = JSONResponse({"state": State.UNKNOWN, "message": "No matching task found."})
	except Exception as e:
		logger.error(e)
		response = JSONResponse({"state": State.UNKNOWN, "message": str(e)})


	logger.devel(response.body)
	return response





