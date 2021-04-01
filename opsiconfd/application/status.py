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

from ..utils import get_fqdn, get_node_name

status_router = APIRouter()

def status_setup(app):
	app.include_router(status_router, prefix="/status")

@status_router.get("/")
def status_overview() -> PlainTextResponse:
	data = (
		"status: ok\n"
		f"version: {__version__} [python-opsi={python_opsi_version}]\n"
		f"date: {datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()}\n"
		f"node: {get_node_name()}\n"
		f"fqdn: {get_fqdn()}\n"
	)
	return PlainTextResponse(data)
