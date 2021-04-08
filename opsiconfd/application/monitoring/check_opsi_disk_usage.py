# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check opsi disk usage
"""

import os
import socket

from OPSI.Types import forceList
from OPSI.System import getDiskSpaceUsage

from opsiconfd.config import config
from opsiconfd.logging import logger
from .utils import State, generate_response


def check_opsi_disk_usage(backend, thresholds={}, opsiresource=None): # pylint: disable=dangerous-default-value, too-many-branches, too-many-locals, too-many-statements
	warning = thresholds.get("warning", "5G")
	critical = thresholds.get("critical", "1G")

	config_server = backend.host_getObjects(id=socket.getfqdn())[0]

	workbench_path = config_server.workbenchLocalUrl
	depot_path = config_server.depotLocalUrl
	repository_path = config_server.repositoryLocalUrl

	dirs = {
		"workbench": workbench_path,
		"depot": depot_path,
		"repository": repository_path
	}

	if opsiresource:
		resources = forceList(opsiresource)
	else:
		resources = ["workbench", "depot", "repository"]
		resources.sort()

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
			path = dirs.get(resource, "")
			if path.startswith("file://"):
				path = path.replace('file://', '')
			if os.path.isdir(path):
				if not resource.startswith('/'):
					resource = '/' + resource
				info = getDiskSpaceUsage(path)
				if info:
					results[resource] = info
	except Exception as err: # pylint: disable=broad-except
		message.append("Not able to check DiskUsage. Error: '{}'".format(err))
		return generate_response(State.UNKNOWN, message)

	if results:
		state = State.OK
		for result, info in results.items():
			available = float(info['available']) / 1073741824 # Byte to GB
			usage = info["usage"] * 100
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
				free_space = 100 - usage
				if free_space <= critical:
					state = State.CRITICAL
					message.append(f"DiskUsage from ressource: '{result}' is critical (available: {free_space:.2f}%).")

				elif free_space <= warning:
					if state != State.CRITICAL:
						state = State.WARNING
					message.append(f"DiskUsage warning from ressource: '{result}' (available: {free_space:.2f}%).")

				else:
					message.append(f"DiskUsage from ressource: '{result}' is ok. (available: {free_space:.2f}%).")
	else:
		state = State.UNKNOWN
		message.append("No results get. Nothing to check.")
	message = " ".join(message)
	return generate_response(state, message)
