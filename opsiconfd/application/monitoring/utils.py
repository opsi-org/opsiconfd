"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from opsiconfd.config import config
from opsiconfd.logging import logger

class State:
	OK = 0
	WARNING = 1
	CRITICAL = 2
	UNKNOWN = 3

	_stateText = ["OK", "WARNING", "CRITICAL", "UNKNOWN"]

	@classmethod
	def text(cls, state):
		return cls._stateText[state]

def generateResponse(state: State, message: str) -> JSONResponse:
	message = f"{State.text(state)}: {message}"
	return JSONResponse({"state": state, "message": message})