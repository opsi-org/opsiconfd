# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
monitoring
"""

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.logging import logger

from .check_client_status import check_client_status
from .check_depot_sync_status import check_depot_sync_status
from .check_locked_products import check_locked_products
from .check_opsi_disk_usage import check_opsi_disk_usage
from .check_opsi_webservice import check_opsi_webservice
from .check_plugin_on_client import check_plugin_on_client
from .check_product_status import check_product_status
from .check_short_product_status import check_short_product_status
from .utils import State

monitoring_router = APIRouter()


def monitoring_setup(app: FastAPI) -> None:
	app.include_router(monitoring_router, prefix="/monitoring")


@monitoring_router.post("{any:path}")
async def monitoring(request: Request) -> JSONResponse:  # pylint: disable=too-many-branches
	backend = get_unprotected_backend()
	request_data = await request.json()
	task = None
	try:
		task = request_data["task"]
	except KeyError:
		logger.error("No task set, nothing to do")
		response = JSONResponse({"state": State.UNKNOWN, "message": "No task set, nothing to do"})

	params = request_data.get("param", {})
	try:
		if task == "checkClientStatus":
			response = check_client_status(
				backend=backend, client_id=params.get("clientId", None), exclude_product_list=params.get("exclude", None)
			)
		elif task == "checkShortProductStatus":
			if params.get("productIds", None):
				product_id = params.get("productIds", None)
			else:
				product_id = params.get("productId", None)
			response = check_short_product_status(backend=backend, product_id=product_id, thresholds=params.get("thresholds", {}))
		elif task == "checkProductStatus":
			response = check_product_status(
				backend=backend,
				product_ids=params.get("productIds", []),
				product_groups=params.get("groupIds", []),
				host_group_ids=params.get("hostGroupIds", []),
				depot_ids=params.get("depotIds", []),
				exclude=params.get("exclude", []),
				verbose=params.get("verbose", False),
				strict=params.get("strict", False),
			)
		elif task == "checkDepotSyncStatus":
			response = check_depot_sync_status(
				backend=backend,
				depot_ids=params.get("depotIds", []),
				product_ids=params.get("productIds", []),
				exclude=params.get("exclude", []),
				strict=params.get("strict", False),
				verbose=params.get("verbose", False),
			)
		elif task == "checkPluginOnClient":
			response = check_plugin_on_client(
				backend=backend,
				host_id=params.get("clientId", []),
				command=params.get("plugin", ""),
				timeout=params.get("timeout", 30),
				wait_for_ending=params.get("waitForEnding", True),
				capture_stderr=params.get("captureStdErr", True),
				statebefore=params.get("state", None),
				output=params.get("output", None),
				encoding=params.get("encoding", None),
			)
		elif task == "checkProductLocks":
			response = check_locked_products(
				backend=backend,
				depot_ids=params.get("depotIds", []),
				product_ids=params.get("productIds", []),
			)
		elif task == "checkOpsiWebservice":
			response = await check_opsi_webservice(
				cpu_thresholds=params.get("cpu", {}), error_thresholds=params.get("errors", {}), perfdata=params.get("perfdata", True)
			)
		elif task == "checkOpsiDiskUsage":
			response = check_opsi_disk_usage(opsiresource=params.get("resource", None))
		else:
			response = JSONResponse({"state": State.UNKNOWN, "message": "No matching task found."})
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		response = JSONResponse({"state": State.UNKNOWN, "message": str(err)})

	return response
