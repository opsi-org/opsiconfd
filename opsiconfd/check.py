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
from re import findall
from typing import Any, Dict, Optional, Union

import requests
from colorama import Fore, Style  # type: ignore[import]
from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import]
from OPSI.System.Posix import (  # type: ignore[import]
	execute,
	isOpenSUSE,
	isRHEL,
	isSLES,
)
from packaging.version import parse as parse_version
from redis.exceptions import ConnectionError as RedisConnectionError
from requests import get
from requests.exceptions import ConnectionError as RequestConnectionError
from requests.exceptions import ConnectTimeout
from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd.backend import get_backend, get_mysql
from opsiconfd.logging import logger
from opsiconfd.utils import decode_redis_result, redis_client

REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/stable/Debian_11/"
PACKAGES = ("opsiconfd", "opsi-utils", "opsipxeconfd")
OPSI_REPO = "https://download.uib.de"
OPSI_PACKAGES_PATH = "4.2/stable/packages/windows/localboot/"
OPSI_PACKAGES = {"opsi-script": "0.0", "opsi-client-agent": "0.0"}


MT_INFO = "info"
MT_SUCCESS = "success"
MT_WARNING = "warning"
MT_ERROR = "error"


def health_check(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Started health check...")
	result = {}
	result["system_packages"] = check_system_packages(print_messages)
	result["opsi_packages"] = check_opsi_packages(print_messages)
	result["redis"] = check_redis(print_messages)
	result["mysql"] = check_mysql(print_messages)
	result["deprecated_calls"] = check_deprecated_calls(print_messages)
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
		logger.error("Could not get package versions from repository.")
		logger.error(str(err))
		return {}
	if repo_data.status_code >= 400:
		logger.error("Could not get package versions from repository: %d - %s.", repo_data.status_code, repo_data.text)
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

	result: Union[Dict[str, Any], str] = {}
	result = {"status": "ok", "details": "All packages up to date.", "partial_checks": {}}
	package_versions = get_repo_versions()
	try:
		if isRHEL() or isSLES():
			cmd = ["yum", "list", "installed"]
			regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+).*$")
			for line in execute(cmd, shell=False, timeout=10):
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
			for line in execute(cmd, shell=False, timeout=10):
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
			for line in execute(cmd, shell=False, timeout=10):
				match = regex.search(line)
				if not match:
					continue
				if match.group(2) in package_versions:
					logger.info("Package '%s' found: version '%s'", match.group(2), match.group(3))
					if match.group(1) == "ii":
						package_versions[match.group(2)]["version_found"] = match.group(3)
	except RuntimeError as err:
		logger.error("Could not get package versions from system: %s", err)
		return {}
	logger.info("Installed packages: %s", package_versions)

	not_installed = 0
	outdated = 0
	for package, info in package_versions.items():
		result["partial_checks"][package] = {}  # pylint: disable=loop-invariant-statement
		if "version_found" not in info:
			result["partial_checks"][package] = {  # pylint: disable=loop-invariant-statement
				"status": "error",
				"details": f"Package '{package}' is not installed.",
			}  # type: ignore[assignment]
			result["status"] = "error"  # pylint: disable=loop-invariant-statement
			not_installed = not_installed + 1
			if print_messages:
				show_message(f"Package {package} should be installed.", MT_ERROR)  # pylint: disable=loop-global-usage
		elif parse_version(info["version"]) > parse_version(info["version_found"]):
			outdated = outdated + 1
			if print_messages:
				show_message(
					f"Package {package} is outdated. Installed version: {info['version_found']} - available version: {info['version']}",
					MT_WARNING,  # pylint: disable=loop-global-usage
				)
			result["status"] = "warn"  # pylint: disable=loop-invariant-statement
			result["partial_checks"][package] = {  # pylint: disable=loop-invariant-statement
				"status": "warn",
				"details": f"Package {package} is outdated. Installed version: {info['version_found']} - available version: {info['version']}",
			}
		else:
			if print_messages:
				show_message(
					f"Package {package} is up to date. Installed version: {info['version_found']}",
					MT_SUCCESS,  # pylint: disable=loop-global-usage
				)
			result["partial_checks"][package] = {  # pylint: disable=loop-invariant-statement
				"status": "ok",
				"details": f"Installed version: {info['version_found']}",
			}
		if not_installed > 0 or outdated > 0:
			result[  # pylint: disable=loop-invariant-statement
				"details"
			] = f"Out of {len(package_versions.keys())} packages checked, {not_installed} are not installed and {outdated} are out of date."
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
	except (RuntimeError, MySQLdbOperationalError, OperationalError) as err:
		logger.debug(err)
		error = str(err)
		if print_messages:
			show_message(f"Could not connect to mysql: {error}", MT_ERROR)
		return {"status": "error", "details": error}


def check_deprecated_calls(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Checking calls of deprecated methods...")
	deprecated_calls = {}
	with redis_client(timeout=5) as redis:
		methods = redis.smembers("opsiconfd:stats:rpcs:deprecated:methods")
		for method_name in methods:
			method_name = method_name.decode("utf-8")
			calls = decode_redis_result(redis.get(f"opsiconfd:stats:rpcs:deprecated:{method_name}:count"))
			clients = decode_redis_result(redis.smembers(f"opsiconfd:stats:rpcs:deprecated:{method_name}:clients"))
			last_call = decode_redis_result(redis.get(f"opsiconfd:stats:rpcs:deprecated:{method_name}:last_call"))
			deprecated_calls[method_name] = {"calls": calls, "last_call": last_call, "clients": clients}

			if print_messages:
				show_message(
					f"Deprecated method '{method_name}' was called {calls} times.", MT_WARNING  # pylint: disable=loop-global-usage
				)  # pylint: disable=loop-global-usage
				show_message("The method was called from:", MT_WARNING)  # pylint: disable=loop-global-usage
				for client in clients:
					show_message(f"\t- {client}", MT_WARNING)  # pylint: disable=loop-global-usage
				show_message(f"Last call was {last_call}", MT_WARNING)  # pylint: disable=loop-global-usage
	if not deprecated_calls:
		if print_messages:
			show_message("No deprecated method calls found.", MT_SUCCESS)
		return {"status": "ok", "details": "No deprecated method calls found."}
	logger.devel(deprecated_calls)
	return {"status": "warn", "details": deprecated_calls}


def check_opsi_packages(print_messages: bool = False) -> dict:  # pylint: disable=too-many-local-variables,too-many-branches
	if print_messages:
		show_message("Checking opsi packages...")
	res = requests.get(f"{OPSI_REPO}/{OPSI_PACKAGES_PATH}", timeout=5)

	avalible_packages = OPSI_PACKAGES
	result = {"status": "ok", "details": "All packages up to date.", "partial_checks": {}}
	partial_checks: Dict[str, Any] = {}
	backend = get_backend()

	not_installed = 0
	outdated = 0

	for filename in findall(r'<a href="(?P<file>[\w\d._-]+\.opsi)">(?P=file)</a>', res.text):
		name, avalible_version = split_name_and_version(filename)

		if name in avalible_packages:  # pylint: disable=loop-invariant-statement
			avalible_packages[name] = avalible_version  # pylint: disable=loop-invariant-statement

	depots = backend.host_getIdents(type="OpsiDepotserver")  # pylint: disable=no-member
	for depot in depots:
		if print_messages:
			show_message(f"Checking versions on depot {depot}")
		partial_checks[depot] = {}
		for package, avalible_version in avalible_packages.items():
			try:  # pylint: disable=loop-try-except-usage
				product_on_depot = backend.productOnDepot_getObjects(productId=package, depotId=depot)[0]  # pylint: disable=no-member
				not_installed = not_installed + 1
			except IndexError as error:
				logger.debug(error)
				msg = f"Package '{package}' is not installed."
				if print_messages:
					show_message(
						f"	{msg}",
						MT_ERROR,  # pylint: disable=loop-global-usage
					)
				result["status"] = "error"  #  pylint: disable=loop-invariant-statement
				partial_checks[depot][package] = {
					"status": "error",
					"details": msg,
				}
				continue
			if parse_version(avalible_version) > parse_version(f"{product_on_depot.productVersion}-{product_on_depot.packageVersion}"):
				msg = (
					f"Package '{package}' is outdated. Installed version: {product_on_depot.productVersion}-{product_on_depot.packageVersion}"
					f"- avalible Version: {avalible_version}"
				)
				if print_messages:
					show_message(
						f"	{msg}",
						MT_ERROR,  # pylint: disable=loop-global-usage
					)
				result["status"] = "error"  #  pylint: disable=loop-invariant-statement
				partial_checks[depot][package] = {  #  pylint: disable=loop-invariant-statement
					"status": "error",
					"details": msg,
				}
				outdated = outdated + 1
			else:
				if print_messages:
					show_message(
						f"	Package {package} on is up to date. Installed version: {product_on_depot.productVersion}-{product_on_depot.packageVersion}",
						MT_SUCCESS,  # pylint: disable=loop-global-usage
					)
				partial_checks[depot][package] = {  #  pylint: disable=loop-invariant-statement
					"status": "ok",
					"details": f"Installed version: {product_on_depot.productVersion}-{product_on_depot.packageVersion}.",
				}

	if not_installed > 0 or outdated > 0:
		result["details"] = (
			f"Out of {len(OPSI_PACKAGES.keys())} packages on {len(depots)} depots checked, "
			f"{not_installed} are not installed and {outdated} are out of date."
		)
	else:
		if print_messages:
			show_message("No deprecated method calls found.", MT_SUCCESS)

	result["partial_checks"] = partial_checks
	return result


def split_name_and_version(filename: str) -> tuple:
	match = re.search(r"(?P<name>[\w_-]+)_(?P<version>.+-.+)\.opsi", filename)
	if not match:
		raise ValueError(f"Unable to split software name and version from {filename}")
	return (match.group("name"), match.group("version"))


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
