# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""


import os
import re
import sys
from typing import Any, Dict, Optional

from colorama import Fore, Style  # type: ignore[import]
from MySQLdb import OperationalError as MySQLdbOperationalError
from OPSI.System.Posix import (  # type: ignore[import]
	execute,
	isOpenSUSE,
	isRHEL,
	isSLES,
)
from packaging.version import parse
from redis.exceptions import ConnectionError as RedisConnectionError
from requests import get
from requests.exceptions import ConnectionError as RequestConnectionError
from requests.exceptions import ConnectTimeout
from sqlalchemy.exc import OperationalError as SqlalchemyOperationalError

from opsiconfd.backend import get_mysql
from opsiconfd.logging import logger
from opsiconfd.utils import decode_redis_result, redis_client

REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/stable/Debian_11/"
PACKAGES = ("opsiconfd", "opsi-utils", "opsipxeconfd")


MT_INFO = "info"
MT_SUCCESS = "success"
MT_WARNING = "warning"
MT_ERROR = "error"


def health_check(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Started health check...")
	result = {}
	result["system_packages"] = check_system_packages(print_messages)
	result["redis"] = check_redis(print_messages)
	result["mysql"] = check_mysql(print_messages)
	if print_messages:
		show_message("Health check done...")
	return result


def get_repo_versions() -> Dict[str, Any]:
	url = REPO_URL
	packages = PACKAGES
	repo_data = None

	package_versions: Dict[str, Dict[str, Any]] = {}

	try:
		repo_data = get(url, timeout=10)
	except (RequestConnectionError, ConnectTimeout) as err:
		logger.error(str(err))
	if not repo_data or repo_data.status_code >= 400:
		logger.error("Could not get package versions from repository.")
		return {}
	for package in packages:
		package_versions[package] = {"version": "0", "status": None}

		match = re.search(f"{package}_(.+?).tar.gz", repo_data.text)  # pylint: disable=dotted-import-in-loop
		if match:
			version = match.group(1)
			package_versions[package]["version"] = version
			logger.debug("Available version for %s: %s.", package, version)
	return package_versions


def check_system_packages(print_messages: bool = False) -> dict:  # pylint: disable=too-many-branches, too-many-statements
	if print_messages:
		show_message("Checking system packages...")
	result: Dict[str, Dict[str, Any]] = {}

	package_versions = get_repo_versions()

	if isRHEL() or isSLES():
		cmd = ["yum", "list", "installed"]
		regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+).*$")
		for line in execute(cmd, shell=False):
			match = regex.search(line)
			if not match:
				continue
			p_name = match.group(1).split(".")[0]
			if p_name in package_versions:
				logger.info("Package '%s' found: version '%s'", p_name, match.group(2))
				package_versions[p_name]["version_found"] = match.group(2)
	elif isOpenSUSE():
		cmd = ["zypper", "search", "-is", "opsi*"]
		regex = re.compile(r"^[^S]\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+).*$")
		for line in execute(cmd, shell=False):
			match = regex.search(line)
			if not match:
				continue
			p_name = match.group(1)
			if p_name in package_versions:
				logger.info("Package '%s' found: version '%s'", p_name, match.group(3))
				package_versions[p_name]["version_found"] = match.group(3)
	else:
		cmd = ["dpkg", "-l"]  # pylint: disable=use-tuple-over-list
		regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*$")
		for line in execute(cmd, shell=False):
			match = regex.search(line)
			if not match:
				continue
			if match.group(2) in package_versions:
				logger.info("Package '%s' found: version '%s'", match.group(2), match.group(3))
				if match.group(1) == "ii":
					package_versions[match.group(2)]["version_found"] = match.group(3)
	logger.info("Installed packages: %s", package_versions)

	for package, info in package_versions.items():
		result[package] = {}
		if "version_found" not in info:
			result[package] = {"status": "error", "details": f"Package '{package}' is not installed."}
			if print_messages:
				show_message(f"Package {package} should be installed.", MT_ERROR)  # pylint: disable=loop-global-usage
		elif parse(info.get("version", "0")) > parse(info.get("version_found", "0")):
			if print_messages:
				show_message(
					f"Package {package} is outdated. Installed version: {info.get('version_found')} - available version: {info.get('version')}",
					MT_WARNING,  # pylint: disable=loop-global-usage
				)
			result[package] = {
				"status": "warn",
				"details": f"Installed version: {info.get('version_found')} - available version: {info.get('version')}",
			}
		else:
			if print_messages:
				show_message(
					f"Package {package} is up to date. Installed version: {info.get('version_found')}",
					MT_SUCCESS,  # pylint: disable=loop-global-usage
				)
			result[package] = {"status": "ok", "details": f"Installed version: {info.get('version_found')}"}
	return result


def check_redis(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Checking redis...")
	try:
		with redis_client(timeout=5, test_connection=True) as redis:
			redis_info = decode_redis_result(redis.execute_command("INFO"))
			logger.info(redis_info)
			modules = [module["name"] for module in redis_info["modules"]]
			if "timeseries" not in modules:
				if print_messages:
					show_message("Redis-Timeseries not loaded.", MT_ERROR)
				return {"status": "err", "details": "Redis-Timeseries not loaded."}
			if print_messages:
				show_message("Redis is running and Redis-Timeseries is loaded.", MT_SUCCESS)
			return {"status": "ok", "details": "Redis is running and Redis-Timeseries is loaded."}
	except RedisConnectionError as err:
		logger.info(str(err))
		if print_messages:
			show_message("Cannot connect to redis!", MT_ERROR)
		return {"status": "error", "details": str(err)}


def check_mysql(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Checking mysql...")
	try:
		with get_mysql().session() as mysql_client:
			mysql_client.execute("SHOW TABLES;")
		if print_messages:
			show_message("Connection to mysql is working.", MT_SUCCESS)
		return {"status": "ok", "details": "Connection to mysql is working."}
	except (RuntimeError, MySQLdbOperationalError, SqlalchemyOperationalError) as err:
		logger.debug(err)
		error = str(err)
		if print_messages:
			show_message(f"Could not connect to mysql: {error}", MT_ERROR)
		return {"status": "error", "details": error}


def show_message(message: str, msg_type: str = MT_INFO, newline: bool = True, msg_format: Optional[str] = None, log: bool = False) -> None:
	if log:
		log_level = "info"
		if msg_type == MT_WARNING:
			log_level = "warning"
		elif msg_type == MT_ERROR:
			log_level = "error"
		exc_info = msg_type == MT_ERROR
		getattr(logger, log_level)(message, exc_info=exc_info)

	# colorama: color and style https://github.com/tartley/colorama
	color = Fore.WHITE
	if msg_type == MT_WARNING:
		color = Fore.YELLOW
	elif msg_type == MT_ERROR:
		color = Fore.RED
	elif msg_type == MT_SUCCESS:
		color = Fore.GREEN
	if msg_format:
		message = msg_format % message
	if os.getenv("ANSI_COLORS_DISABLED") is None:
		message = color + Style.BRIGHT + message + Style.RESET_ALL

	sys.stdout.write(message)
	if newline:
		sys.stdout.write("\n")
	sys.stdout.flush()
