# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
status - available without authentication
"""

import datetime

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from OPSI import __version__ as python_opsi_version
from .. import __version__

from ..config import FQDN
from ..utils import get_node_name, get_aredis_info, aredis_client
from ..ssl import get_ca_info, get_cert_info
status_router = APIRouter()

def status_setup(app):
	app.include_router(status_router, prefix="/status")

@status_router.get("/")
async def status_overview() -> PlainTextResponse:
	status = "ok"
	redis_status = "ok"
	redis_error = ""
	redis_mem = -1
	redis_mem_total = -1
	try:
		redis = await aredis_client(timeout=3)
		await redis.ping()
		redis_info = await get_aredis_info(redis)
		redis_mem_total = redis_info['used_memory']
		for key_type in redis_info["key_info"]:
			redis_mem += redis_info["key_info"][key_type]["memory"]
		redis_status = "ok"
	except Exception as err:  # pylint: disable=broad-except
		redis_status = "error"
		status = "error"
		redis_error = str(err) or "connection error"

	data = (
		f"status: {status}\n"
		f"version: {__version__} [python-opsi={python_opsi_version}]\n"
		f"date: {datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()}\n"
		f"node: {get_node_name()}\n"
		f"fqdn: {FQDN}\n"
		f"redis-status: {redis_status}\n"
		f"redis-error: {redis_error}\n"
		f"redis-mem: {redis_mem}\n"
		f"redis-mem-total: {redis_mem_total}\n"
		f"ssl-ca-valid-days: {get_ca_info()['expiration']}\n"
		f"ssl-cert-valid-days: {get_cert_info()['expiration']}\n"
	)
	return PlainTextResponse(data)
