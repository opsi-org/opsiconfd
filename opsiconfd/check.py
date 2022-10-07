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
import requests
from packaging.version import parse
from redis.exceptions import ConnectionError

from opsiconfd.utils import (
	async_get_redis_info,
	async_redis_client,
	decode_redis_result,
)

from .config import config
from .logging import logger

# TODO change to stable
REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/development/Debian_11/"


def health_check() -> None:
	logger.notice("Started health check...")
	check_system_packages()
	check_redis()
	logger.notice("Health check done...")


def check_system_packages() -> None:
	logger.notice("Checking packages...")
	packages = ["opsiconfd", "opsi-utils", "opsipxeconfd"]
	package_versions = {}
	for package in packages:
		package_versions[package] = {"version": "0", "version_found": "0", "status": None}
		repo_data = requests.get(REPO_URL, timeout=60)
		match = re.search(f"{package}_(.+?).tar.gz", repo_data.text)
		if match:
			found = match.group(1)
			package_versions[package]["version"] = found
			logger.debug(found)
	regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*$")
	for line in run_command(["dpkg", "-l"], shell=False, log_command=True, log_output=False).split("\n"):
		match = regex.search(line)
		if not match:
			continue
		if match.group(2) in package_versions:
			logger.info("Package '%s' found: version '%s', status '%s'", match.group(2), match.group(3), match.group(1))
			package_versions[match.group(2)]["version_found"] = match.group(3)
			package_versions[match.group(2)]["status"] = match.group(1)
	logger.info(package_versions)

	for package, info in package_versions.items():
		if info.get("status") != "ii":
			logger.error("Package %s should be installed.", package)
		elif parse(info.get("version", "0")) > parse(info.get("version_found", "0")):  # type: ignore
			logger.warning(
				"Package %s is outdated. Installed version: %s - avalible Version: %s",
				package,
				info.get("version_found", "0"),
				info.get("version", "0"),
			)

		else:
			logger.info("Package %s is up to date", package)


def check_redis() -> None:
	logger.notice("Checking redis...")
	try:
		redis_client = redis.StrictRedis.from_url(config.redis_internal_url)
		redis_info = decode_redis_result(redis_client.execute_command("INFO"))
		logger.info(redis_info)
	except ConnectionError as err:
		logger.error("Cannot connect to redis!")
		logger.info(str(err))


def run_command(cmd: List[str], shell: bool = False, log_command: bool = True, log_output: bool = True) -> str:
	if log_command:
		logger.info("Executing: %s", cmd)

	try:
		out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=shell).decode("utf-8").strip()
		if log_output:
			logger.debug(out)
	except subprocess.CalledProcessError as err:
		out = err.output.decode("utf-8", "replace")
		logger.error("Command failed: %s", err)
		if log_output:
			logger.error(out)
		raise
	return out
