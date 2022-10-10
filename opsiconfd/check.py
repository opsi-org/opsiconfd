# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""


import re
import subprocess
from typing import List

import redis
from OPSI.System.Posix import (  # type: ignore[import]
	execute,
	isOpenSUSE,
	isRHEL,
	isSLES,
)
from packaging.version import parse
from redis.exceptions import ConnectionError as RedisConnectionError
from requests import get

from opsiconfd.utils import decode_redis_result

from .config import config as opsiconfd_config
from .logging import logger

# TODO change to stable
REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/development/Debian_11/"


def health_check() -> dict:
	logger.notice("Started health check...")
	result = {}
	result["packages"] = check_system_packages()
	result["redis"] = check_redis()
	result["mysql"] = check_mysql()
	logger.notice("Health check done...")
	return result


def check_system_packages() -> dict:  # pylint: disable=too-many-branches
	logger.notice("Checking packages...")
	packages = ("opsiconfd", "opsi-utils", "opsipxeconfd")
	package_versions = {}  # type: ignore[var-annotated]
	result = {}  # type: ignore[var-annotated]
	url = REPO_URL
	for package in packages:
		package_versions[package] = {"version": "0", "version_found": "0", "status": None}
		repo_data = get(url, timeout=60)
		match = re.search(f"{package}_(.+?).tar.gz", repo_data.text)  # pylint: disable=dotted-import-in-loop
		if match:
			found = match.group(1)
			package_versions[package]["version"] = found
			logger.debug(found)

	if isOpenSUSE() or isRHEL() or isSLES():
		cmd = ["yum", "list", "installed"]
		regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+).*$")
		for line in execute(cmd, shell=False):
			match = regex.search(line)
			if not match:
				continue
			p_name = match.group(1).split(".")[0]
			if p_name in package_versions:
				print("Package '%s' found: version '%s', status '%s'", p_name, match.group(2), "ii")
				package_versions[p_name]["version_found"] = match.group(2)
				package_versions[p_name]["status"] = "ii"
	else:
		cmd = ["dpkg", "-l"]  # pylint: disable=use-tuple-over-list
		regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*$")
		for line in execute(cmd, shell=False):
			match = regex.search(line)
			if not match:
				continue
			if match.group(2) in package_versions:
				logger.info("Package '%s' found: version '%s', status '%s'", match.group(2), match.group(3), match.group(1))
				package_versions[match.group(2)]["version_found"] = match.group(3)
				package_versions[match.group(2)]["status"] = match.group(1)
	logger.info(package_versions)

	for package, info in package_versions.items():
		result[package] = {}
		if info.get("status") != "ii":
			result[package] = {"status": "error"}
			logger.error("Package %s should be installed.", package)
		elif parse(info.get("version", "0")) > parse(info.get("version_found", "0")):  # type: ignore
			logger.warning(
				"Package %s is outdated. Installed version: %s - avalible version: %s",
				package,
				info.get("version_found", "0"),
				info.get("version", "0"),
			)
			result[package] = {
				"status": "warn",
				"details": f"Installed version: {info.get('version_found')} - avalible version: {info.get('version')}",
			}

		else:
			logger.info("Package %s is up to date", package)
			result[package] = {"status": "ok"}
	return result


def check_redis() -> dict:
	logger.notice("Checking redis...")
	try:
		redis_client = redis.StrictRedis.from_url(opsiconfd_config.redis_internal_url)
		redis_info = decode_redis_result(redis_client.execute_command("INFO"))
		logger.info(redis_info)
		modules = [module["name"] for module in redis_info["modules"]]
		if "timeseries" not in modules:
			return {"status": "err", "details": "Redis-Timeseries not loaded."}
		return {"status": "ok"}
	except RedisConnectionError as err:
		logger.error("Cannot connect to redis!")
		logger.info(str(err))
		return {"status": "error", "details": str(err)}


def check_mysql() -> dict:
	logger.notice("Checking mysql...")
	mysql_data = {"module": "", "config": {}}

	with open("/etc/opsi/backends/mysql.conf", encoding="utf-8") as config_file:
		exec(config_file.read(), mysql_data)  # pylint: disable=exec-used

	mysql_config = mysql_data["config"]
	try:
		execute(
			[
				"mysql",
				f"--user={mysql_config.get('username')}",  # type: ignore[attr-defined]
				f"--password={mysql_config.get('password')}",  # type: ignore[attr-defined]
				f"--host={mysql_config.get('address')}",  # type: ignore[attr-defined]
				f"--database={mysql_config.get('database')}",  # type: ignore[attr-defined]
				"-e",
				"SHOW TABLES;",
			],
			shell=False,
		)
		return {"status": "ok"}
	except subprocess.CalledProcessError as err:
		return {"status": "error", "details": err.output.decode("utf-8", "replace")}
