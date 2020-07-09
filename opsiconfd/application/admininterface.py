"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""


import os

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..logging import logger
from ..config import config
from ..backend import get_client_backend, get_backend_interface

admin_interface_router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(config.static_dir, "templates"))

def admin_interface_setup(app):
	app.include_router(admin_interface_router, prefix="/admin")

@admin_interface_router.get("/?")
async def admin_interface_index(request: Request):
	context = {
		"request": request,
		"interface": get_backend_interface()
	}
	return templates.TemplateResponse("admininterface.html", context)
