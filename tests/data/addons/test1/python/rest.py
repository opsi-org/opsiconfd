# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
addon test1 - rest
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

api_router = APIRouter()


@api_router.get("/{any:path}")
def route_get() -> JSONResponse:
	return JSONResponse("TEST1")
