# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check plugin on client
"""

from fastapi.responses import JSONResponse

from OPSI.Types import forceList  # type: ignore[import]

from opsiconfd.logging import logger
from .utils import State, generate_response, ERRORCODE_PATTERN


def check_plugin_on_client(  # pylint: disable=line-too-long, too-many-arguments, too-many-branches, too-many-locals, too-many-statements
	backend, host_id, command, timeout=30, wait_for_ending=True, capture_stderr=True, statebefore=None, output=None, encoding=None
) -> JSONResponse:

	state = State.OK
	message = ""
	host_id = forceList(host_id)

	try:  # pylint: disable=too-many-nested-blocks
		result = backend.hostControlSafe_reachable(hostIds=host_id)
		if result.get(host_id[0], False):
			checkresult = backend.hostControlSafe_execute(
				command=command,
				hostIds=host_id,
				waitForEnding=wait_for_ending,
				captureStderr=capture_stderr,
				encoding=encoding,
				timeout=timeout,
			)
			checkresult = checkresult.get(host_id[0], None)
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
							if errorcode <= 3:
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
				return generate_response(int(statebefore), output)
			else:
				message = f"Can't check host '{host_id[0]}' is not reachable."
				state = State.UNKNOWN
	except Exception as err:  # pylint: disable=broad-except
		state = State.UNKNOWN
		message = str(err)

	return generate_response(state, message)
