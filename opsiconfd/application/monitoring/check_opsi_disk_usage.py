"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""
import orjson
import os

from fastapi.responses import JSONResponse

from OPSI.Types import forceList
from OPSI.System import getDiskSpaceUsage

from opsiconfd.logging import logger
from opsiconfd.config import config

from .utils import State, generateResponse 


def check_opsi_disk_usage(thresholds={}, opsiresource=None):
	warning = thresholds.get("warning", "5G")
	critical = thresholds.get("critical", "1G")

	if opsiresource:
		resources = forceList(opsiresource)
	else:
		resources = []
		resources.append(config.static_dir)
		resources.sort()

	logger.devel("resources: %s", resources)

	if warning.lower().endswith("g"):
		unit = "GB"
		warning = float(warning[:-1])
		critical = float(critical[:-1])
	elif warning.lower().endswith("%"):
		unit = "%"
		warning = float(warning[:-1])
		critical = float(critical[:-1])
	else:
		unit = "%"
		warning = float(warning)
		critical = float(critical)

	results = {}
	state = State.OK
	message = []

	try:
		for resource in resources:
			path = config.static_dir
			if os.path.isdir(path):
				if not resource.startswith('/'):
					resource = u'/' + resource

				info = getDiskSpaceUsage(path)
				results[resource] = info
				logger.devel(results[resource])
	except Exception as e:
		message.append("Not able to check DiskUsage. Error: '{}'".format(e))
		return generateResponse(State.UNKNOWN, message)


	
	if results:
		state = State.OK
		for result, info in results.items():
			logger.devel("info available: %s", info["available"])
			available = float(info['available']) / 1073741824 # Byte to GB
			usage = info["usage"] * 100
			logger.devel("usage %s", info["usage"] )
			logger.devel("available: %s", available)
			if unit == "GB":
				if available <= critical:
					state = State.CRITICAL
					message.append(f"DiskUsage from ressource: '{result}' is critical (available: {available:.2f}GB).")
				elif available <= warning:
					if state != State.CRITICAL:
						state = State.WARNING
					message.append(f"DiskUsage warning from ressource: '{result}' (available: {available:.2f}GB).")
				else:
					message.append(f"DiskUsage from ressource '{result}' is ok. (available:  {available:.2f}GB).")
			elif unit == "%":
				freeSpace = 100 - usage
				if freeSpace <= critical:
					state = State.CRITICAL
					message.append(f"DiskUsage from ressource: '{result}' is critical (available: {freeSpace:.2f}%).")

				elif freeSpace <= warning:
					if state != State.CRITICAL:
						state = State.WARNING
					message.append(f"DiskUsage warning from ressource: '{result}' (available: {freeSpace:.2f}%).")

				else:
					message.append(f"DiskUsage from ressource: '{result}' is ok. (available: {freeSpace:.2f}%).")

	else:
		state = State.UNKNOWN
		message.append("No results get. Nothing to check.")


	message = " ".join(message)



	return generateResponse(state, message)