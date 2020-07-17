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

def redis_interface_setup(app):
	app.include_router(admin_interface_router, prefix="/redis-interface")



@admin_interface_router.post("/?")
async def redis_command(request: Request, response: Response):
	redis_client = await get_redis_client()
	logger.notice(request)
	try:
		request_body = await request.json()
		redis_cmd = request_body.get("cmd")
		redis_result = await redis_client.execute_command(redis_cmd)
		
		if type(redis_result) == list:
			
			result = []
			for value in redis_result:
				logger.notice(value)
				result.append(value.decode("utf8"))
			logger.warning(result)
		else:
			result = redis_result.decode("utf8")
		
		response = JSONResponse({"status": 200, "error": None, "data": {"result": result}})
	except Exception as e:
		logger.warning(e)
		response = JSONResponse({"status": 500, "error": {"detail": str(e)}})

	return response
