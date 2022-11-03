# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
The opsi configuration service.
"""

from fastapi import FastAPI
from OPSI import __version__ as python_opsi_version  # type: ignore[import]

from .. import __version__
from ..rest import RestApiValidationError


class OpsiconfdApp(FastAPI):
	def __init__(self) -> None:
		super().__init__(
			title="opsiconfd",
			description="",
			version=f"{__version__} [python-opsi={python_opsi_version}]",
			responses={422: {"model": RestApiValidationError, "description": "Validation Error"}},
		)
		self.is_shutting_down = False


app = OpsiconfdApp()


@app.on_event("startup")
async def startup_event() -> None:
	from .main import startup  # pylint: disable=import-outside-toplevel

	await startup()


@app.on_event("shutdown")
async def shutdown_event() -> None:
	from .main import shutdown  # pylint: disable=import-outside-toplevel

	await shutdown()
