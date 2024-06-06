# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check opsi disk usage
"""

from __future__ import annotations

from fastapi.responses import JSONResponse
from opsicommon.types import forceList

from opsiconfd.config import DEPOT_DIR, REPOSITORY_DIR, WORKBENCH_DIR
from opsiconfd.utils import get_disk_usage

from .utils import State, generate_response


def check_opsi_disk_usage(thresholds: dict[str, str] | None = None, opsiresource: list[str] | None = None) -> JSONResponse:
	thresholds = thresholds or {}
	opsiresource = opsiresource or []
	warning = thresholds.get("warning", "5G")
	critical = thresholds.get("critical", "1G")

	dirs = {"workbench": WORKBENCH_DIR, "depot": DEPOT_DIR, "repository": REPOSITORY_DIR}

	if opsiresource:
		resources = forceList(opsiresource)
	else:
		resources = ["workbench", "depot", "repository"]
		resources.sort()

	warning_flt = 0.0
	critical_flt = 0.0
	if warning.lower().endswith("g"):
		unit = "GB"
		warning_flt = float(warning[:-1])
		critical_flt = float(critical[:-1])
	elif warning.lower().endswith("%"):
		unit = "%"
		warning_flt = float(warning[:-1])
		critical_flt = float(critical[:-1])
	else:
		unit = "%"
		warning_flt = float(warning)
		critical_flt = float(critical)

	results = {}
	state = State.OK
	message: list[str] = []

	try:
		for resource in resources:
			path = dirs.get(resource)
			if path:
				results[resource] = get_disk_usage(path).as_dict()
	except Exception as err:
		return generate_response(State.UNKNOWN, f"Not able to check DiskUsage: {err}")

	if results:
		state = State.OK
		for result, info in results.items():
			available = float(info["available"]) / 1073741824  # Byte to GB
			usage = info["usage"] * 100
			if unit == "GB":
				if available <= critical_flt:
					state = State.CRITICAL
					message.append(f"DiskUsage from ressource: '{result}' is critical (available: {available:.2f}GB).")
				elif available <= warning_flt:
					if state != State.CRITICAL:
						state = State.WARNING
					message.append(f"DiskUsage warning from ressource: '{result}' (available: {available:.2f}GB).")
				else:
					message.append(f"DiskUsage from ressource '{result}' is ok. (available:  {available:.2f}GB).")
			elif unit == "%":
				free_space = 100 - usage
				if free_space <= critical_flt:
					state = State.CRITICAL
					message.append(f"DiskUsage from ressource: '{result}' is critical (available: {free_space:.2f}%).")

				elif free_space <= warning_flt:
					if state != State.CRITICAL:
						state = State.WARNING
					message.append(f"DiskUsage warning from ressource: '{result}' (available: {free_space:.2f}%).")
				else:
					message.append(f"DiskUsage from ressource: '{result}' is ok. (available: {free_space:.2f}%).")
	else:
		state = State.UNKNOWN
		message.append("No disk usage results, nothing to check.")
	return generate_response(state, " ".join(message))
