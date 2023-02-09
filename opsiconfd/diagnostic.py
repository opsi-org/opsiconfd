# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
diagnostic
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from subprocess import run
from typing import Any

import psutil

from opsiconfd import __version__
from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check import get_disk_mountpoints, get_installed_packages, health_check
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.utils import running_in_docker

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


def get_licenses() -> dict[str, Any]:
	backend = get_unprotected_backend()
	return backend.backend_getLicensingInfo()


def get_opsi_product_versions() -> dict:
	backend = get_unprotected_backend()
	pods = backend.productOnDepot_getObjects(attributes=["id", "name", "productVersion", "packageVersion"])
	result: dict = {}
	for pod in pods:
		backend.productOnDepot_getObjects("")
		if not result.get(pod.depotId):
			result[pod.depotId] = {}
		result[pod.depotId][pod.productId] = {"version": pod.version, "type": pod.productType}
	return result


def get_processor_info() -> dict[str, Any]:
	cmd = "lscpu"
	all_info = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
	for line in all_info.split("\n"):
		if "Model name" in line:
			model = re.sub(".*Model name.*:", "", line, 1).strip()

	# https://psutil.readthedocs.io/en/latest/#psutil.getloadavg
	return {"model": model, "cpu_count": psutil.cpu_count(), "load_avg": psutil.getloadavg()}


def get_memory_info() -> dict[str, Any]:
	# https://psutil.readthedocs.io/en/latest/#psutil.virtual_memory
	memory = psutil.virtual_memory()
	total = memory.total
	available = memory.available
	return {
		"total": total,
		"available": available,
		"total_human": f"{round(total / 1024 / 1024 / 1024, 2)}GB",
		"available_human": f"{round(available / 1024 / 1024 / 1024, 2)}GB",
		"used_percent": memory.percent,
	}


def get_disk_info() -> dict[str, int | str]:
	mountpoints = get_disk_mountpoints()
	result: dict = {}
	for mountpoint in mountpoints:
		disk = psutil.disk_usage(mountpoint)
		result[mountpoint] = {
			"total": disk.total,
			"used": disk.used,
			"free": disk.free,
			"total_human": f"{disk.total / (2**30)}GB",
			"used_human": f"{disk.used / (2**30)}GB",
			"free_human": f"{disk.free / (2**30)}GB",
		}
	return result


def get_backendmanager_extension_files() -> list:
	path = "/etc/opsi/backendManager/extend.d"
	if os.path.exists(path):
		return os.listdir(path)
	return []


def get_config() -> dict[str, Any]:
	conf = config.items().copy()
	for key in ["ssl_server_key_passphrase", "ssl_ca_key_passphrase"]:
		conf[key] = "********"
	conf["grafana_internal_url"] = re.sub(r"//.*:.*@", "//user:*****@", conf["grafana_internal_url"], flags=re.IGNORECASE)
	return conf


def get_diagnostic_data() -> dict[str, Any]:

	data = {
		"processor": get_processor_info(),
		"memory": get_memory_info(),
		"disks": get_disk_info(),
		"docker": running_in_docker(),
		"os_release": get_os_release(),
		"lsb_release": get_lsb_release(),
		"config": get_config(),
		"depots": get_depot_info(),
		"clients": get_client_info(),
		"products": get_opsi_product_versions(),
		"packages": get_installed_packages(),
		"backendmanager_extension_files": get_backendmanager_extension_files(),
		"licenses": get_licenses(),
		"health_check": list(health_check()),
	}
	return data
