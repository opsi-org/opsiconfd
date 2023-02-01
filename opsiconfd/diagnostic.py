# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
diagnostic
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from subprocess import run
from typing import Any

from opsiconfd import __version__
from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check import health_check
from opsiconfd.config import config
from opsiconfd.logging import logger

OS_RELEASE_FILE = "/etc/os-release"
LSB_RELASE_COMMAND = ["lsb_release", "-a"]


def get_os_release() -> dict[str, str]:
	data: dict[str, str] = {}
	os_release_file = Path(OS_RELEASE_FILE)
	if os_release_file.exists():
		regex = re.compile(r'^\s*([^#]\S+)\s*=\s*"?([^"]+)"?')
		for line in os_release_file.read_text(encoding="utf-8").splitlines():
			match = regex.match(line)
			if match:
				data[match.group(1).upper()] = match.group(2)
	return data


def get_lsb_release() -> dict[str, str]:
	data: dict[str, str] = {}
	try:
		lines = run(
			LSB_RELASE_COMMAND, shell=False, check=False, text=True, encoding="utf-8", capture_output=True, timeout=5
		).stdout.splitlines()
	except Exception as err:  # pylint: disable=broad-except
		logger.info("lsb_release not available: %s", err)
		return data

	for line in lines:
		if ":" not in line:
			continue
		key, val = line.split(":", 1)
		data[key.strip().upper().replace(" ", "_")] = val.strip()
	return data


def get_client_info() -> dict[str, int]:
	now = datetime.now()
	backend = get_unprotected_backend()
	data: dict[str, int] = {"client_count": 0, "active_client_count": 0}

	for host in backend.host_getObjects(type="OpsiClient", attributes=["id", "lastSeen"]):
		data["client_count"] += 1  # type: ignore[operator]
		if host.lastSeen and (now - datetime.fromisoformat(host.lastSeen)).days < 365:
			data["active_client_count"] += 1  # type: ignore[operator]

	return data


def get_depot_info() -> dict[str, list[str]]:
	backend = get_unprotected_backend()
	return {"ids": backend.host_getIdents(returnType="str", type="OpsiDepotserver")}


def get_diagnostic_data() -> dict[str, Any]:
	# licenses
	# package versions
	# product versions
	# processor info and usage
	# ram info and usage
	# backendmanager extension files
	data = {
		"os_release": get_os_release(),
		"lsb_release": get_lsb_release(),
		"config": config.items(),  # TODO: remove sensible data
		"depots": get_depot_info(),
		"clients": get_client_info(),
		"health_check": list(health_check()),
	}
	return data
