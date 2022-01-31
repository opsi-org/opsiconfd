# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
The opsi configuration service.
"""

from OPSI import __version__ as python_opsi_version  # type: ignore[import]

from fastapi import FastAPI

from .. import __version__
from ..rest import RestApiValidationError


class OpsiconfdApp(FastAPI):
	def __init__(self):
		super().__init__(
			title="opsiconfd",
			description="",
			version=f"{__version__} [python-opsi={python_opsi_version}]",
			responses={422: {"model": RestApiValidationError, "description": "Validation Error"}},
		)
		self.is_shutting_down = False


app = OpsiconfdApp()


@app.on_event("startup")
async def startup_event():
	from .main import startup  # pylint: disable=import-outside-toplevel

	await startup()
