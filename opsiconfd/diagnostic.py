# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
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
from subprocess import CalledProcessError, run
from typing import Any

import psutil
from starlette.concurrency import run_in_threadpool

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.main import health_check
from opsiconfd.check.system import get_disk_mountpoints, get_installed_packages
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.redis import async_get_redis_info, async_redis_client
from opsiconfd.utils import running_in_docker

OS_RELEASE_FILE = "/etc/os-release"
LSB_RELASE_COMMAND = ["lsb_release", "-a"]


def get_os_release() -> dict[str, str]:
	logger.debug("get_os_release")
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
	logger.debug("get_lsb_release")
	data: dict[str, str] = {}
	try:
		lines = run(
			LSB_RELASE_COMMAND, shell=False, check=False, text=True, encoding="utf-8", capture_output=True, timeout=5
		).stdout.splitlines()
	except Exception as err:
		logger.debug("lsb_release not available: %s", err)
		return data

	for line in lines:
		if ":" not in line:
			continue
		key, val = line.split(":", 1)
		data[key.strip().upper().replace(" ", "_")] = val.strip()

	if data["DISTRIBUTOR_ID"] == "Univention":
		data["UCS_ROLE"] = run(
			["ucr", "get", "server/role"], shell=False, check=False, text=True, encoding="utf-8", capture_output=True, timeout=5
		).stdout.strip()
	return data


def get_client_info() -> dict[str, int]:
	logger.debug("get_client_info")
	now = datetime.now()
	backend = get_unprotected_backend()
	data: dict[str, int] = {"client_count": 0, "active_client_count": 0}

	for host in backend.host_getObjects(type="OpsiClient", attributes=["id", "lastSeen"]):
		data["client_count"] += 1  # type: ignore[operator]
		if host.lastSeen and (now - datetime.fromisoformat(host.lastSeen)).days < 365:
			data["active_client_count"] += 1  # type: ignore[operator]

	return data


def get_depot_info() -> dict[str, list[str]]:
	logger.debug("get_depot_info")
	backend = get_unprotected_backend()
	return {"ids": backend.host_getIdents(returnType="str", type="OpsiDepotserver")}


def get_licenses() -> dict[str, Any]:
	logger.debug("get_licenses")
	backend = get_unprotected_backend()
	return backend.backend_getLicensingInfo()


def get_opsi_product_versions() -> dict:
	logger.debug("get_opsi_product_versions")
	backend = get_unprotected_backend()
	pods = backend.productOnDepot_getObjects(attributes=["id", "name", "productVersion", "packageVersion"])
	result: dict = {}
	for pod in pods:
		if not result.get(pod.depotId):
			result[pod.depotId] = {}
		result[pod.depotId][pod.productId] = {"version": pod.version, "type": pod.productType}
	return result


def get_processor_info() -> dict[str, Any]:
	logger.debug("get_processor_info")
	try:
		all_info = Path("/proc/cpuinfo").read_text(encoding="utf-8")
		vendor = ""
		model = ""
		flags: list[str] = []
		bugs: list[str] = []
		for line in all_info.split("\n"):
			if ":" not in line:
				continue
			attribute, value = line.split(":", 1)
			attribute = attribute.strip().lower()
			value = value.strip()
			if attribute == "model name":
				model = value
			elif attribute == "vendor_id":
				vendor = value
			elif attribute == "flags":
				flags = value.split(" ")
			elif attribute == "bugs":
				bugs = value.split(" ")

		return {
			"vendor": vendor,
			"model": model,
			"flags": flags,
			"bugs": bugs,
			"cpu_count": psutil.cpu_count(),
			# https://psutil.readthedocs.io/en/latest/#psutil.getloadavg
			"load_avg": psutil.getloadavg(),
		}
	except FileNotFoundError:
		logger.warning("Could not read '/proc/cpuinfo'.")
		return {}


def get_memory_info() -> dict[str, Any]:
	logger.debug("get_memory_info")
	# https://psutil.readthedocs.io/en/latest/#psutil.virtual_memory
	memory = psutil.virtual_memory()
	total = memory.total
	available = memory.available
	return {
		"total": total,
		"available": available,
		"total_human": f"{round(total / (2 ** 30), 2)}GiB",
		"available_human": f"{round(available / (2 ** 30), 2)}GiB",
		"used_percent": memory.percent,
	}


def get_disk_info() -> dict[str, int | str]:
	logger.debug("get_disk_info")
	mountpoints = get_disk_mountpoints()
	result: dict = {}
	for mountpoint in mountpoints:
		disk = psutil.disk_usage(mountpoint)
		result[mountpoint] = {
			"total": disk.total,
			"used": disk.used,
			"free": disk.free,
			"total_human": f"{disk.total / (2**30)}GiB",
			"used_human": f"{disk.used / (2**30)}GiB",
			"free_human": f"{disk.free / (2**30)}GiB",
		}
	return result


def get_backendmanager_extension_methods() -> dict[str, Any]:
	logger.debug("get_backendmanager_extension_methods")
	backend = get_unprotected_backend()
	result: dict = {}
	for method in backend._extender_method_info:
		signature = []
		for param in method.signature.parameters.values():
			signature.append({param.name: str(param.annotation)})
		result[method.name] = {"signature": signature, "file": str(method.file), "overwrite": method.overwrite}
	return result


def get_config() -> dict[str, Any]:
	logger.debug("get_config")
	conf = config.items().copy()
	for key in ["ssl_server_key_passphrase", "ssl_ca_key_passphrase"]:
		conf[key] = "********"
	conf["grafana_internal_url"] = re.sub(r"//.*:.*@", "//user:*****@", conf["grafana_internal_url"])
	return conf


def get_system_info() -> dict:
	logger.debug("get_system_info")
	result: dict = {}
	product_name = Path("/sys/devices/virtual/dmi/id/product_name")
	try:
		result["product_name"] = product_name.read_text(encoding="utf-8").strip()
	except (FileNotFoundError, PermissionError):
		logger.warning("Could not read '%s'", product_name)
		result["product_name"] = None

	docker = running_in_docker()
	result["docker"] = docker

	try:
		cmd = ["hostnamectl", "status"]
		hostnamectl = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout.strip()
		result.update(
			{key_value[0].strip(): key_value[1].strip() for line in hostnamectl.split("\n") if len(key_value := line.split(":", 1)) == 2}
		)
	except (FileNotFoundError, CalledProcessError):
		logger.warning("hostnamectl command not found.")

	return result


def get_network_info() -> dict:
	logger.debug("get_network_info")
	result: dict = {}
	try:
		# https://psutil.readthedocs.io/en/latest/#psutil.net_if_addrs
		for interface, addresses in psutil.net_if_addrs().items():
			result[interface] = []
			for address in addresses:
				result[interface].append(
					{
						"family": address.family.name,
						"address": address.address,
						"netmask": address.netmask,
						"broadcast": address.broadcast,
						"point to point": address.ptp,
					}
				)
		for interface, stats in psutil.net_if_stats().items():
			result[interface].append(
				{
					"is up": stats.isup,
					"duplex": stats.duplex,
					"speed": stats.speed,
					"mtu": stats.mtu,
					"flags": stats.flags,
				}
			)

	except Exception as err:
		logger.error("get_network_info failed: %s", err)

	return result


def get_proxy_vars() -> dict[str, str]:
	logger.debug("get_proxy_vars")
	proxy_vars = {}
	for var in ["http_proxy", "https_proxy", "no_proxy"]:
		proxy_vars[var] = os.environ.get(var, "")
	return proxy_vars


async def get_diagnostic_data() -> dict[str, Any]:
	def _get_sync_data() -> dict[str, Any]:
		return {
			"system": get_system_info(),
			"processor": get_processor_info(),
			"memory": get_memory_info(),
			"disks": get_disk_info(),
			"os_release": get_os_release(),
			"lsb_release": get_lsb_release(),
			"network": get_network_info(),
			"proxy_vars": get_proxy_vars(),
			"config": get_config(),
			"depots": get_depot_info(),
			"clients": get_client_info(),
			"products": get_opsi_product_versions(),
			"packages": get_installed_packages(),
			"backendmanager_extensions": get_backendmanager_extension_methods(),
			"licenses": get_licenses(),
			"health_check": list(health_check()),
		}

	data = await run_in_threadpool(_get_sync_data)
	data["redis_info"] = await async_get_redis_info(await async_redis_client())
	return data
