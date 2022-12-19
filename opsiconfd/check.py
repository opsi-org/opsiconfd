# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""

import re
from enum import StrEnum
from re import findall
from subprocess import run
from typing import Any, Dict, Optional, Union

import requests
from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import]
from opsicommon.system.info import linux_distro_id_like_contains  # type: ignore[import]
from packaging.version import parse as parse_version
from redis.exceptions import ConnectionError as RedisConnectionError
from requests import get
from requests.exceptions import ConnectionError as RequestConnectionError
from requests.exceptions import ConnectTimeout
from rich.console import Console
from rich.padding import Padding
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


class CheckStatus(StrEnum):
	OK = "ok"
	WARNING = "warning"
	ERROR = "error"


STYLES = {CheckStatus.OK: "[bold green]", CheckStatus.WARNING: "[bold yellow]", CheckStatus.ERROR: "[bold red]"}
INDENT_SIZE = 5


def health_check() -> dict:
	result = {}
	result["system_packages"] = check_system_packages()
	result["opsi_packages"] = check_opsi_packages()
	result["redis"] = check_redis()
	result["mysql"] = check_mysql()
	result["licenses"] = check_opsi_licenses()
	result["deprecated_calls"] = check_deprecated_calls()
	return result


def console_health_check() -> int:
	console = Console(log_time=False)
	checks = {
		"system packages": {"check_method": check_system_packages, "print_method": print_check_system_packages_result},
		"opsi packages": {"check_method": check_opsi_packages, "print_method": print_check_opsi_packages_result},
		"Redis": {"check_method": check_redis, "print_method": print_check_redis_result},
		"MySQL": {"check_method": check_mysql, "print_method": print_check_mysql_result},
		"opsi licenses": {"check_method": check_opsi_licenses, "print_method": print_check_opsi_licenses_results},
		"deprecated calls": {
			"check_method": check_deprecated_calls,
			"print_method": print_check_deprecated_calls_result,
		},
	}
	res = 0
	console.print("Checking server health...")
	with console.status("Checking...", spinner="arrow3"):
		for name, check in checks.items():
			result = check["check_method"]()  # type: ignore
			if result.get("status") == CheckStatus.OK:
				console.print(f"[bold green] {name}: {CheckStatus.OK.upper()} ")
			elif result.get("status") == CheckStatus.WARNING:
				console.print(f"[bold yellow] {name}: {CheckStatus.WARNING.upper()} ")
				res = 2
			else:
				console.print(f"[bold red] {name}: {CheckStatus.ERROR.upper()} ")
				res = 1
			if config.detailed:
				check["print_method"](result, console)  # type: ignore
	console.print("Done")
	return res


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


def check_system_packages() -> dict:  # pylint: disable=too-many-branches, too-many-statements, unused-argument
	result: Union[Dict[str, Any], str] = {}
	result = {"status": CheckStatus.OK, "message": "All packages are up to date.", "partial_checks": {}}
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
				"status": CheckStatus.ERROR,
				"message": f"Package '{package}' is not installed.",
			}
			result["status"] = CheckStatus.ERROR  # pylint: disable=loop-invariant-statement
			not_installed = not_installed + 1
		elif parse_version(info["version"]) > parse_version(info["version_found"]):
			outdated = outdated + 1
			result["status"] = CheckStatus.WARNING  # pylint: disable=loop-invariant-statement
			result["partial_checks"][package] = {  # pylint: disable=loop-invariant-statement
				"status": CheckStatus.WARNING,
				"message": f"Package {package} is out of date. Installed version: {info['version_found']} - available version: {info['version']}",
				"details": {"version": info["version_found"], "available_version": info["version"], "outdated": True},
			}
		else:
			result["partial_checks"][package] = {  # pylint: disable=loop-invariant-statement
				"status": CheckStatus.OK,
				"message": f"Installed version: {info['version_found']}",
				"details": {"version": info["version_found"]},
			}
	result["details"] = {"packages": len(package_versions.keys()), "not_installed": not_installed, "outdated": outdated}
	if not_installed > 0 or outdated > 0:
		result[
			"message"
		] = f"Out of {len(package_versions.keys())} packages checked, {not_installed} are not installed and {outdated} are out of date."
	return result


def check_redis() -> dict:  # pylint: disable=unused-argument
	try:
		with redis_client(timeout=5, test_connection=True) as redis:
			redis_info = decode_redis_result(redis.execute_command("INFO"))
			logger.info(redis_info)
			modules = [module["name"] for module in redis_info["modules"]]
			if "timeseries" not in modules:
				return {
					"status": CheckStatus.ERROR,
					"message": "RedisTimeSeries not loaded.",
					"details": {"connection": True, "timeseries": False},
				}
			return {"status": CheckStatus.OK, "message": "Redis is running and RedisTimeSeries is loaded."}
	except RedisConnectionError as err:
		logger.info(str(err))
		return {"status": CheckStatus.ERROR, "message": str(err), "details": {"connection": False, "timeseries": False, "error": str(err)}}


def check_mysql() -> dict:  # pylint: disable=unused-argument
	try:
		with get_mysql().session() as mysql_client:
			mysql_client.execute("SHOW TABLES;")
		return {"status": CheckStatus.OK, "message": "Connection to MySQL is working."}
	except (RuntimeError, MySQLdbOperationalError, OperationalError) as err:
		logger.debug(err)
		error = str(err)
		return {"status": CheckStatus.ERROR, "message": error}


def check_deprecated_calls() -> dict:  # pylint: disable=unused-argument
	redis_prefix_stats = config.redis_key("stats")
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
		return {"status": CheckStatus.OK, "message": "No deprecated method calls found."}
	return {
		"status": CheckStatus.WARNING,
		"message": f"Use of {len(deprecated_calls)} deprecated methods found.",
		"details": deprecated_calls,
	}


def check_opsi_packages() -> dict:  # pylint: disable=too-many-locals,too-many-branches,unused-argument
	res = requests.get(f"{OPSI_REPO}/{OPSI_PACKAGES_PATH}", timeout=5)

	available_packages = OPSI_PACKAGES
	result = {"status": CheckStatus.OK, "details": "All packages are up to date.", "partial_checks": {}}
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
				result["status"] = CheckStatus.ERROR  # pylint: disable=loop-invariant-statement
				partial_checks[depot][package] = {
					"status": CheckStatus.ERROR,
					"message": msg,
				}
				continue
			if parse_version(available_version) > parse_version(f"{product_on_depot.productVersion}-{product_on_depot.packageVersion}"):
				msg = (
					f"Package '{package}' is outdated. Installed version: {product_on_depot.productVersion}-{product_on_depot.packageVersion}"
					f"- available version: {available_version}"
				)
				result["status"] = CheckStatus.ERROR  # pylint: disable=loop-invariant-statement
				partial_checks[depot][package] = {"status": CheckStatus.ERROR, "message": msg}  # pylint: disable=loop-invariant-statement
				outdated = outdated + 1
			else:
				partial_checks[depot][package] = {  # pylint: disable=loop-invariant-statement
					"status": CheckStatus.OK,
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


def check_opsi_licenses() -> dict:  # pylint: disable=unused-argument
	result = {"status": CheckStatus.OK, "clients": 0}
	partial_checks = {}

	backend = get_unprotected_backend()
	licensing_info = backend.backend_getLicensingInfo()  # pylint: disable=no-member
	result["clients"] = licensing_info["client_numbers"]["all"]
	for module, module_data in licensing_info.get("modules", {}).items():  # pylint: disable=use-dict-comprehension
		if module_data["state"] == "free":
			continue
		if module_data["state"] == "close_to_limit":
			if result["status"] != CheckStatus.ERROR:  # pylint: disable=loop-invariant-statement
				result["status"] = CheckStatus.WARNING  # pylint: disable=loop-invariant-statement
			partial_checks[module] = {  # pylint: disable=loop-invariant-statement
				"status": CheckStatus.WARNING,
				"details": {"state": module_data["state"], "client_number": module_data["client_number"]},
				"message": f"License for module '{module}' is close to the limit.",
			}
		elif module_data["state"] == "over_limit":
			result["state"] = CheckStatus.WARNING  # pylint: disable=loop-invariant-statement
			partial_checks[module] = {  # pylint: disable=loop-invariant-statement
				"status": "error",
				"details": {"state": module_data["state"], "client_number": module_data["client_number"]},
				"message": f"License for module '{module}' is over the limit.",
			}
		else:
			partial_checks[module] = {  # pylint: disable=loop-invariant-statement
				"status": CheckStatus.OK,
				"details": {"state": module_data["state"], "client_number": module_data["client_number"]},
				"message": f"License for module '{module}' is valid.",
			}
	result["partial_checks"] = partial_checks
	return result


def split_name_and_version(filename: str) -> tuple:
	match = re.search(r"(?P<name>[\w_-]+)_(?P<version>.+-.+)\.opsi", filename)
	if not match:
		raise ValueError(f"Unable to split software name and version from {filename}")
	return (match.group("name"), match.group("version"))


# check result print functions


def print(msg: str, console: Console, style: Optional[str] = "", indent_level: int = 0) -> None:
	indent_size = 5
	console.print(Padding(f"{style}{msg}", (0, indent_size * indent_level)))  # pylint: disable=loop-global-usage


def print_check_deprecated_calls_result(check_result: dict, console: Console) -> None:
	print(check_result["message"], console, STYLES[check_result["status"]], 1)
	for method, data in check_result.get("details", {}).items():
		print(f"Deprecated method '{method}' was called {data.get('calls')} times.", console, STYLES[check_result["status"]], 1)
		print("The method was called from:", console, STYLES[check_result["status"]], 1)
		for client in data.get("clients"):
			print(f"- {client}", console, STYLES[check_result["status"]], 2)

		print(f"Last call was {data.get('last_call')}", console, STYLES[check_result["status"]], 1)


def print_check_opsi_licenses_results(check_result: dict, console: Console) -> None:
	print(f"Active clients: {check_result['clients']}", console, indent_level=1)

	for module, data in check_result["partial_checks"].items():
		print(f"{module}:", console, indent_level=1)
		print(f"- {data['message']}", console, STYLES.get(data["status"]), 2)
		print(f"- Client limit: {data['details']['client_number']}", console, STYLES.get(data["status"]), 2)


def print_check_opsi_packages_result(check_result: dict, console: Console) -> None:

	msg = (
		f"Out of {len(OPSI_PACKAGES.keys())} packages on {len(check_result.get('partial_checks', {}).keys())} depots checked, "
		f"{check_result['details'].get('not_installed')} are not installed and {check_result['details'].get('outdated')} are out of date."
	)
	print(msg, console, STYLES.get(check_result["status"]), 1)
	for depot, depot_results in check_result.get("partial_checks", {}).items():
		print(f"{depot}:", console, indent_level=1)
		for res in depot_results.values():
			print(f"{res['message']}", console, STYLES.get(check_result["status"]), 2)


def print_check_redis_result(check_result: dict, console: Console) -> None:
	print(check_result["message"], console, STYLES[check_result["status"]], 1)


def print_check_mysql_result(check_result: dict, console: Console) -> None:
	print(check_result["message"], console, STYLES[check_result["status"]], 1)


def print_check_system_packages_result(check_result: dict, console: Console) -> None:
	for package, data in check_result["partial_checks"].items():
		msg: str = ""
		details = data.get("details", {})
		if details.get("version"):
			if details.get("outdated"):
				msg = (
					f"Package {package} is out of date. Installed version: {details['version']}"
					"- available version: {details['available_version']}"
				)
			else:
				msg = f"Package {package} is up to date. Installed version: {details['version']}"
		else:
			msg = f"Package {package} should be installed."
		print(msg, console, STYLES[data["status"]], 1)
