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
from subprocess import run
from typing import Any, Callable, Dict, Optional, Union

import requests
from colorama import Fore, Style  # type: ignore[import]
from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import]
from opsicommon.system.info import linux_distro_id_like_contains  # type: ignore[import]
from packaging.version import parse as parse_version
from redis.exceptions import ConnectionError as RedisConnectionError
from requests import get
from requests.exceptions import ConnectionError as RequestConnectionError
from requests.exceptions import ConnectTimeout
from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd.backend import get_mysql, get_unprotected_backend
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.utils import decode_redis_result, redis_client

REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/stable/Debian_11/"
PACKAGES = ("opsiconfd", "opsi-utils", "opsipxeconfd")
OPSI_REPO = "https://download.uib.de"
OPSI_PACKAGES_PATH = "4.2/stable/packages/windows/localboot/"
OPSI_PACKAGES = {"opsi-script": "0.0", "opsi-client-agent": "0.0"}

MSG_WIDTH = 50
MT_INFO = "info"
MT_SUCCESS = "success"
MT_WARNING = "warning"
MT_ERROR = "error"


def messages(message: str, width: int) -> Callable:
	def message_decorator(function: Callable) -> Callable:
		def wrapper(*args: Any, **kwargs: Dict[str, Any]) -> Any:  # pylint: disable=too-many-branches
			try:
				print_messages = args[0]
			except IndexError:
				print_messages = kwargs.get("print_messages")
			if print_messages:
				show_message("	- " + message + ":", newline=False, msg_format="%-" + str(width) + "s")
			result = function(*args, **kwargs)
			if print_messages:
				if result.get("status") == "ok":
					show_message("OK", MT_SUCCESS)
				elif result.get("status") == "warn":
					show_message("WARNING", MT_WARNING)
				else:
					show_message("ERROR", MT_ERROR)
				if config.detailed:
					if function.__name__ == "check_system_packages":
						print_check_system_packages_result(result)
					elif function.__name__ == "check_redis":
						print_check_redis_result(result)
					elif function.__name__ == "check_mysql":
						print_check_mysql_result(result)
					elif function.__name__ == "check_deprecated_calls":
						print_check_deprecated_calls_result(result)
					elif function.__name__ == "check_opsi_packages":
						print_check_opsi_packages_result(result)
					elif function.__name__ == "check_opsi_licenses":
						print_check_opsi_licenses_results(result)

			return result
		return wrapper
	return message_decorator


def health_check(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Started health check...")
	result = {}
	result["system_packages"] = check_system_packages(print_messages)
	result["opsi_packages"] = check_opsi_packages(print_messages)
	result["redis"] = check_redis(print_messages)
	result["mysql"] = check_mysql(print_messages)
	result["licenses"] = check_opsi_licenses(print_messages)
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


@messages("Checking system packages", MSG_WIDTH)
def check_system_packages(print_messages: bool = False) -> dict:  # pylint: disable=too-many-branches, too-many-statements, unused-argument
	result: Union[Dict[str, Any], str] = {}
	result = {"status": "ok", "message": "All packages up to date.", "partial_checks": {}}
	package_versions = get_repo_versions()
	try:
		if linux_distro_id_like_contains(("sles", "rhel")):
			cmd = ["yum", "list", "installed"]
			regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+).*$")
			res = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
			for line in res.split("\n"):
				match = regex.search(line)
				if not match:
					continue
				p_name = match.group(1).split(".")[0]
				if p_name in package_versions:
					logger.info("Package '%s' found: version '%s'", p_name, match.group(2))
					package_versions[p_name]["version_found"] = match.group(2)
		elif linux_distro_id_like_contains("opensuse"):
			cmd = ["zypper", "search", "-is", "opsi*"]
			regex = re.compile(r"^[^S]\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+).*$")
			res = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
			for line in res.split("\n"):
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
			res = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
			for line in res.split("\n"):
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
		if not result["partial_checks"][package].get("details"):  # pylint: disable=loop-invariant-statement
			result["partial_checks"][package]["details"] = {}  # pylint: disable=loop-invariant-statement
		if "version_found" not in info:

			result["partial_checks"][package] = {  # pylint: disable=loop-invariant-statement
				"details": {"version": None},
				"status": "error",
				"message": f"Package '{package}' is not installed.",
			}  # type: ignore[assignment]
			result["status"] = "error"  # pylint: disable=loop-invariant-statement
			not_installed = not_installed + 1
		elif parse_version(info["version"]) > parse_version(info["version_found"]):
			outdated = outdated + 1
			result["status"] = "warn"  # pylint: disable=loop-invariant-statement
			result["partial_checks"][package] = {  # pylint: disable=loop-invariant-statement
				"status": "warn",
				"message": f"Package {package} is outdated. Installed version: {info['version_found']} - available version: {info['version']}",
				"details": {"version": info["version_found"], "available_version": info["version"], "outdated": True},
			}
		else:
			result["partial_checks"][package] = {  # pylint: disable=loop-invariant-statement
				"status": "ok",
				"message": f"Installed version: {info['version_found']}",
				"details": {"version": info["version_found"]},
			}
	result["details"] = {"packages": len(package_versions.keys()), "not_installed": not_installed, "outdated": outdated}
	if not_installed > 0 or outdated > 0:
		result[
			"message"
		] = f"Out of {len(package_versions.keys())} packages checked, {not_installed} are not installed and {outdated} are out of date."
	return result


def print_check_system_packages_result(check_result: dict) -> None:
	for package, data in check_result["partial_checks"].items():
		details = data.get("details", {})
		if details.get("version"):
			if details.get("outdated"):
				show_message(
					f"		Package {package} is outdated. Installed version: {details['version']} - available version: {details['available_version']}",
					MT_WARNING,  # pylint: disable=loop-global-usage
				)
			else:
				show_message(
					f"		Package {package} is up to date. Installed version: {details['version']}",
					MT_SUCCESS,  # pylint: disable=loop-global-usage
				)
		else:
			show_message(f"		Package {package} should be installed.", MT_ERROR)  # pylint: disable=loop-global-usage


@messages("Checking redis", MSG_WIDTH)
def check_redis(print_messages: bool = False) -> dict:  # pylint: disable=unused-argument
	try:
		with redis_client(timeout=5, test_connection=True) as redis:
			redis_info = decode_redis_result(redis.execute_command("INFO"))
			logger.info(redis_info)
			modules = [module["name"] for module in redis_info["modules"]]
			if "timeseries" not in modules:
				return {"status": "error", "message": "Redis-Timeseries not loaded.", "details": {"connection": True, "timeseries": False}}
			return {"status": "ok", "message": "Redis is running and Redis-Timeseries is loaded."}
	except RedisConnectionError as err:
		logger.info(str(err))
		return {"status": "error", "message": str(err) , "details": {"connection": False, "timeseries": False, "error": str(err)}}


def print_check_redis_result(check_result: dict) -> None:
	if check_result["status"] == "ok":
		show_message("		Redis is running and Redis-Timeseries is loaded.", MT_SUCCESS)
	else:
		if check_result["details"]["connection"]:
			show_message("		Redis-Timeseries not loaded.", MT_ERROR)
		else:
			show_message("		Cannot connect to redis!", MT_ERROR)


@messages("Checking mysql", MSG_WIDTH)
def check_mysql(print_messages: bool = False) -> dict:  # pylint: disable=unused-argument
	try:
		with get_mysql().session() as mysql_client:
			mysql_client.execute("SHOW TABLES;")
		return {"status": "ok", "message": "Connection to mysql is working."}
	except (RuntimeError, MySQLdbOperationalError, OperationalError) as err:
		logger.debug(err)
		error = str(err)
		return {"status": "error", "message": error}


def print_check_mysql_result(check_result: dict) -> None:
	if check_result.get("status") == "ok":
		show_message("		Connection to mysql is working.", MT_SUCCESS)
	else:
		show_message(f"		Could not connect to mysql: {check_result.get('message')}", MT_ERROR)


@messages("Checking calls of deprecated methods", MSG_WIDTH)
def check_deprecated_calls(print_messages: bool = False) -> dict:  # pylint: disable=unused-argument
	redis_prefix_stats = config.redis_key('stats')
	deprecated_calls = {}
	with redis_client(timeout=5) as redis:
		methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
		for method_name in methods:
			method_name = method_name.decode("utf-8")
			calls = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:count"))
			clients = decode_redis_result(redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:clients"))
			last_call = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:last_call"))
			deprecated_calls[method_name] = {"calls": calls, "last_call": last_call, "clients": clients}
	if not deprecated_calls:
		return {"status": "ok", "message": "No deprecated method calls found."}
	return {"status": "warn", "details": deprecated_calls}


def print_check_deprecated_calls_result(check_result: dict) -> None:
	if check_result.get("status") == "ok":
		show_message("		No deprecated method calls found.", MT_SUCCESS)
	else:
		for method, data in check_result.get("details", {}).items():
			show_message(
				f"		Deprecated method '{method}' was called {data.get('calls')} times.", MT_WARNING  # pylint: disable=loop-global-usage
			)
			show_message("		The method was called from:", MT_WARNING)  # pylint: disable=loop-global-usage
			for client in data.get('clients'):
				show_message(f"		\t- {client}", MT_WARNING)  # pylint: disable=loop-global-usage
			show_message(f"		Last call was {data.get('last_call')}", MT_WARNING)  # pylint: disable=loop-global-usage


@messages("Checking opsi packages", MSG_WIDTH)
def check_opsi_packages(print_messages: bool = False) -> dict:  # pylint: disable=too-many-locals,too-many-branches,unused-argument
	res = requests.get(f"{OPSI_REPO}/{OPSI_PACKAGES_PATH}", timeout=5)

	available_packages = OPSI_PACKAGES
	result = {"status": "ok", "details": "All packages up to date.", "partial_checks": {}}
	partial_checks: Dict[str, Any] = {}
	backend = get_unprotected_backend()

	not_installed = 0
	outdated = 0

	for filename in findall(r'<a href="(?P<file>[\w\d._-]+\.opsi)">(?P=file)</a>', res.text):
		name, available_version = split_name_and_version(filename)

		if name in available_packages:  # pylint: disable=loop-invariant-statement
			available_packages[name] = available_version  # pylint: disable=loop-invariant-statement

	depots = backend.host_getIdents(type="OpsiDepotserver")  # pylint: disable=no-member
	for depot in depots:
		partial_checks[depot] = {}
		for package, available_version in available_packages.items():
			try:  # pylint: disable=loop-try-except-usage
				product_on_depot = backend.productOnDepot_getObjects(productId=package, depotId=depot)[0]  # pylint: disable=no-member
				not_installed = not_installed + 1
			except IndexError as error:
				logger.debug(error)
				msg = f"Package '{package}' is not installed."
				result["status"] = "error"  # pylint: disable=loop-invariant-statement
				partial_checks[depot][package] = {
					"status": "error",
					"message": msg,
				}
				continue
			if parse_version(available_version) > parse_version(f"{product_on_depot.productVersion}-{product_on_depot.packageVersion}"):
				msg = (
					f"Package '{package}' is outdated. Installed version: {product_on_depot.productVersion}-{product_on_depot.packageVersion}"
					f"- available version: {available_version}"
				)
				result["status"] = "error"  # pylint: disable=loop-invariant-statement
				partial_checks[depot][package] = {"status": "error", "message": msg}  # pylint: disable=loop-invariant-statement
				outdated = outdated + 1
			else:
				partial_checks[depot][package] = {  # pylint: disable=loop-invariant-statement
					"status": "ok",
					"message": f"Installed version: {product_on_depot.productVersion}-{product_on_depot.packageVersion}.",
				}
	result["details"] = {"packages": len(OPSI_PACKAGES.keys()), "depots": len(depots), "not_installed": not_installed, "outdated": outdated}
	if not_installed > 0 or outdated > 0:
		result["message"] = (
			f"Out of {len(OPSI_PACKAGES.keys())} packages on {len(depots)} depots checked, "
			f"{not_installed} are not installed and {outdated} are out of date."
		)
	result["partial_checks"] = partial_checks
	return result


def print_check_opsi_packages_result(check_result: dict) -> None:
	msg_type = MT_ERROR
	if check_result.get("status") == "ok":
		msg_type = MT_SUCCESS
	msg = (
		f"		Out of {len(OPSI_PACKAGES.keys())} packages on {len(check_result.get('partial_checks', {}).keys())} depots checked, "
		f"{check_result['details'].get('not_installed')} are not installed and {check_result['details'].get('outdated')} are out of date."
	)
	show_message(msg, msg_type)


@messages("Checking licenses", MSG_WIDTH)
def check_opsi_licenses(print_messages: bool = False) -> dict:  # pylint: disable=unused-argument
	result = {"status": "ok", "clients": 0}
	partial_checks = {}

	backend = get_unprotected_backend()
	licensing_info = backend.backend_getLicensingInfo()  # pylint: disable=no-member
	result["clients"] = licensing_info["client_numbers"]["all"]
	for module, module_data in licensing_info.get("modules", {}).items():  # pylint: disable=use-dict-comprehension
		if module_data["state"] == "free":
			continue
		if module_data["state"] == "close_to_limit":
			if result["status"] != "error":  # pylint: disable=loop-invariant-statement
				result["status"] = "warn"  # pylint: disable=loop-invariant-statement
			partial_checks[module] = {  # pylint: disable=loop-invariant-statement
				"status": "warn",
				"details": {"state": module_data["state"], "client_number": module_data["client_number"]},
				"message": f"License for module '{module}' is close to the limit."
			}
		elif module_data["state"] == "over_limit":
			result["state"] = "warn"  # pylint: disable=loop-invariant-statement
			partial_checks[module] = {  # pylint: disable=loop-invariant-statement
				"status": "error",
				"details": {"state": module_data["state"], "client_number": module_data["client_number"]},
				"message": f"License for module '{module}' is over the limit."
			}
		else:
			partial_checks[module] = {  # pylint: disable=loop-invariant-statement
				"status": "ok",
				"details": {"state": module_data["state"], "client_number": module_data["client_number"]},
				"message": f"License for module '{module}' is valid."
			}
	result["partial_checks"] = partial_checks
	return result


def print_check_opsi_licenses_results(check_result: dict) -> None:
	show_message(f"\t\tActive clients: {check_result['clients']}")
	for module, data in check_result["partial_checks"].items():
		show_message(f"\t\t{module}:")
		status = MT_SUCCESS  # pylint: disable=loop-global-usage
		if data["status"] == "warn":
			status = MT_WARNING  # pylint: disable=loop-global-usage
		elif data["status"] == "error":
			status = MT_ERROR  # pylint: disable=loop-global-usage
		show_message(f"\t\t\t- {data['message']}", status)
		show_message(f"\t\t\t- Client limit: {data['details']['client_number']}", status)


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
