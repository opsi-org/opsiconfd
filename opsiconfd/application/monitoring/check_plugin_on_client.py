"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""
from fastapi.responses import JSONResponse

from OPSI.Types import forceList

from opsiconfd.logging import logger
from .utils import State, generateResponse, ERRORCODE_PATTERN

def check_plugin_on_client(backend, hostId, command, timeout=30, waitForEnding=True, captureStderr=True, statebefore=None, output=None, encoding=None) -> JSONResponse:

	state = State.OK
	message = ""
	hostId = forceList(hostId)

	try:
		result = backend._executeMethod(methodName="hostControl_reachable", hostIds=hostId)
		if result.get(hostId[0], False):
			checkresult = backend._executeMethod(
					methodName="hostControl_execute", 
					command=command, 
					hostIds=hostId, 
					waitForEnding=waitForEnding, 
					captureStderr=captureStderr, 
					encoding=encoding, 
					timeout=timeout
				)
			checkresult = checkresult.get(hostId[0], None)
			if checkresult:
				if checkresult.get("result", None):
					message = checkresult.get("result")[0]
				elif checkresult.get("error", None):
					errormessage = checkresult.get("error", {}).get("message")
					if errormessage:
						logger.debug("Try to find Errorcode")
						match = ERRORCODE_PATTERN.match(errormessage)
						if not match:
							state = State.UNKNOWN
							message = "Unable to parse Errorcode from plugin"
						else:
							errorcode = int(match.group(1))
							command = match.group(2)
							message = match.group(3)
							if not errorcode > 3:
								state = errorcode
							else:
								state = State.UNKNOWN
								message = f"Failed to determine Errorcode from check_command: '{command}', message is: '{message}'"
					else:
						state = State.UNKNOWN
						message = "Unknown Problem by checking plugin on Client. Check your configuration."
				else:
					state = State.UNKNOWN
					message = "Unknown Problem by checking plugin on Client. Check your configuration."
		else:
			if result.get("error", None):
				message = result.get("error").get("message", "")
				state = State.UNKNOWN
			elif statebefore and output:
				return generateResponse(int(statebefore), output)
			else:
				message = f"Can't check host '{hostId[0]}' is not reachable."
				state = State.UNKNOWN
	except Exception as erro:
		state = State.UNKNOWN
		message = str(erro)

	return generateResponse(state, message)

