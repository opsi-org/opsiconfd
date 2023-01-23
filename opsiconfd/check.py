# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""


import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from re import findall
from typing import Any

import requests
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
from rich.console import Console
from rich.padding import Padding
from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd.backend import get_backend, get_mysql
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.utils import decode_redis_result, redis_client

REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/stable/Debian_11/"
PACKAGES = ("opsiconfd", "opsi-utils", "opsipxeconfd")
OPSI_REPO = "https://download.uib.de"
OPSI_PACKAGES_PATH = "4.2/stable/packages/windows/localboot/"
OPSI_PACKAGES = {"opsi-script": "0.0", "opsi-client-agent": "0.0"}


# Can be removed with python 3.11
class StrEnum(str, Enum):
	"""
	Enum where members are also (and must be) strings
	"""

	def __new__(cls, *values):  # type: ignore
		"values must already be of type `str`"
		if len(values) > 3:
			raise TypeError("too many arguments for str(): %r" % (values,))  # pylint: disable=consider-using-f-string
		if len(values) == 1:
			# it must be a string
			if not isinstance(values[0], str):
				raise TypeError("%r is not a string" % (values[0],))  # pylint: disable=consider-using-f-string
		if len(values) >= 2:
			# check that encoding argument is a string
			if not isinstance(values[1], str):
				raise TypeError("encoding must be a string, not %r" % (values[1],))  # pylint: disable=consider-using-f-string
		if len(values) == 3:
			# check that errors argument is a string
			if not isinstance(values[2], str):
				raise TypeError("errors must be a string, not %r" % (values[2]))  # pylint: disable=consider-using-f-string
		value = str(*values)
		member = str.__new__(cls, value)
		member._value_ = value
		return member

	def _generate_next_value_(name, start, count, last_values):  # type: ignore  # pylint: disable=no-self-argument
		"""
		Return the lower-cased version of the member name.
		"""
		return name.lower()


class CheckStatus(StrEnum):
	OK = "ok"
	WARNING = "warning"
	ERROR = "error"


@dataclass(slots=True, kw_only=True)
class PartialCheckResult:
	check_id: str
	check_status: CheckStatus = CheckStatus.OK
	message: str = ""
	details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, kw_only=True)
class CheckResult(PartialCheckResult):
	check_name: str = ""
	check_description: str = ""
	partial_results: list[PartialCheckResult] = field(default_factory=list)

	def add_partial_result(self, partial_result: PartialCheckResult) -> None:
		self.partial_results.append(partial_result)
		if partial_result.check_status == CheckStatus.ERROR:
			self.check_status = CheckStatus.ERROR
		if partial_result.check_status == CheckStatus.WARNING and self.check_status != CheckStatus.ERROR:
			self.check_status = CheckStatus.WARNING


STYLES = {CheckStatus.OK: "[bold green]", CheckStatus.WARNING: "[bold yellow]", CheckStatus.ERROR: "[bold red]"}


def health_check() -> list[CheckResult]:
	return [check_system_packages(), check_opsi_packages(), check_redis(), check_mysql(), check_opsi_licenses(), check_deprecated_calls()]


def console_health_check() -> int:
	console = Console(log_time=False)
	checks = (
		(check_system_packages, print_check_system_packages_result),
		(check_opsi_packages, print_check_opsi_packages_result),
		(check_redis, print_check_result),
		(check_mysql, print_check_result),
		(check_opsi_licenses, print_check_opsi_licenses_results),
		(check_deprecated_calls, print_check_deprecated_calls_result),
	)
	res = 0
	console.print("Checking server health...")
	style = STYLES
	with console.status("Checking...", spinner="arrow3"):
		for check_function, print_function in checks:
			result = check_function()  # type: ignore
			if result.check_status == CheckStatus.OK:
				console.print(f"{style[result.check_status]} {result.check_name}: {CheckStatus.OK.upper()} ")
			elif result.check_status == CheckStatus.WARNING:
				console.print(f"{style[result.check_status]} {result.check_name}: {CheckStatus.WARNING.upper()} ")
				res = 2
			else:
				console.print(f"{style[result.check_status]} {result.check_name}: {CheckStatus.ERROR.upper()} ")
				res = 1
			if config.detailed:
				print_function(result, console)  # type: ignore
	console.print("Done")
	return res


def get_repo_versions() -> dict[str, str | None]:
	url = REPO_URL
	packages = PACKAGES
	repo_data = None

	repo_versions: dict[str, str | None] = {}

	try:
		repo_data = get(url, timeout=10)
	except (RequestConnectionError, ConnectTimeout) as err:
		logger.error("Could not get package versions from repository")
		logger.error(str(err))
		return {}
	if repo_data.status_code >= 400:
		logger.error("Could not get package versions from repository: %d - %s", repo_data.status_code, repo_data.text)
		return {}
	for package in packages:
		repo_versions[package] = None
		match = re.search(f"{package}_(.+?).tar.gz", repo_data.text)  # pylint: disable=dotted-import-in-loop
		if match:
			version = match.group(1)
			repo_versions[package] = version
			logger.debug("Available version for %s: %s", package, version)
	return repo_versions


def check_system_packages() -> CheckResult:  # pylint: disable=too-many-branches, too-many-statements, too-many-locals
	result = CheckResult(
		check_id="system_packages",
		check_name="System packages",
		check_description="Check system package versions",
		message="All packages are up to date.",
	)
	repo_versions = get_repo_versions()
	installed_versions: dict[str, str] = {}
	try:
		if isRHEL() or isSLES():
			cmd = ["yum", "list", "installed"]
			regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+).*$")
			for line in execute(cmd, shell=False, timeout=10):
				match = regex.search(line)
				if not match:
					continue
				p_name = match.group(1).split(".")[0]
				if p_name in repo_versions:
					logger.info("Package '%s' found: version '%s'", p_name, match.group(2))
					installed_versions[p_name] = match.group(2)
		elif isOpenSUSE():
			cmd = ["zypper", "search", "-is", "opsi*"]
			regex = re.compile(r"^[^S]\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+).*$")
			for line in execute(cmd, shell=False, timeout=10):
				match = regex.search(line)
				if not match:
					continue
				p_name = match.group(1)
				if p_name in repo_versions:
					logger.info("Package '%s' found: version '%s'", p_name, match.group(3))
					installed_versions[p_name] = match.group(3)
		else:
			cmd = ["dpkg", "-l"]  # pylint: disable=use-tuple-over-list
			regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*$")
			for line in execute(cmd, shell=False, timeout=10):
				match = regex.search(line)
				if not match or match.group(1) != "ii":
					continue
				p_name = match.group(2)
				if p_name in repo_versions:
					logger.info("Package '%s' found: version '%s'", p_name, match.group(3))
					installed_versions[p_name] = match.group(3)
	except RuntimeError as err:
		error = f"Could not get package versions from system: {err}"
		logger.error(error)
		result.check_status = CheckStatus.ERROR
		result.message = error
		return result

	logger.info("Installed packages: %s", repo_versions)

	not_installed = 0
	outdated = 0
	for package, available_version in repo_versions.items():
		details = {
			"package": package,
			"available_version": available_version,
			"version": installed_versions.get(package),
			"outdated": False,
		}
		partial_result = PartialCheckResult(check_id=f"system_packages:{package}", details=details)
		if not details["version"]:
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"Package '{package}' is not installed."
			not_installed = not_installed + 1
		elif parse_version(available_version or "0") > parse_version(str(details["version"])):
			outdated = outdated + 1
			partial_result.check_status = CheckStatus.WARNING
			partial_result.message = (
				f"Package {package} is out of date. Installed version: {details['version']} - available version: {available_version}"
			)
			details["outdated"] = True
		else:
			partial_result.check_status = CheckStatus.OK
			partial_result.message = f"Package {package} is up to date. Installed version: {details['version']}"
		result.add_partial_result(partial_result)

	result.details = {"packages": len(repo_versions.keys()), "not_installed": not_installed, "outdated": outdated}
	if not_installed > 0 or outdated > 0:
		result.message = (
			f"Out of {len(repo_versions.keys())} packages checked, {not_installed} are not installed and {outdated} are out of date."
		)
	return result


def check_redis() -> CheckResult:
	result = CheckResult(check_id="redis", check_name="Redis server", check_description="Check Redis server state")
	try:
		with redis_client(timeout=5, test_connection=True) as redis:
			redis_info = decode_redis_result(redis.execute_command("INFO"))
			logger.debug("Redis info: %s", redis_info)
			modules = [module["name"] for module in redis_info["modules"]]
			if "timeseries" not in modules:
				result.check_status = CheckStatus.ERROR
				result.message = "RedisTimeSeries not loaded."
				result.details = {"connection": True, "timeseries": False}
			else:
				result.check_status = CheckStatus.OK
				result.message = "Redis is running and RedisTimeSeries is loaded."
	except RedisConnectionError as err:
		logger.info(err)
		result.check_status = CheckStatus.ERROR
		result.message = f"Cannot connect to Redis: {err}"
		result.details = {"connection": False, "timeseries": False, "error": str(err)}
	return result


def check_mysql() -> CheckResult:
	result = CheckResult(check_id="mysql", check_name="MySQL server", check_description="Check MySQL server state")
	try:
		with get_mysql().session() as mysql_client:
			mysql_client.execute("SHOW TABLES;")
		result.check_status = CheckStatus.OK
		result.message = "Connection to MySQL is working."
	except (RuntimeError, MySQLdbOperationalError, OperationalError) as err:
		logger.debug(err)
		result.check_status = CheckStatus.ERROR
		result.message = f"Could not connect to MySQL: {err}"
	return result


def check_deprecated_calls() -> CheckResult:
	result = CheckResult(
		check_id="deprecated_calls",
		check_name="Deprecated RPCs",
		check_description="Check use of deprecated RPC methods",
		message="No deprecated method calls found.",
	)

	redis_prefix_stats = "opsiconfd:stats"
	deprecated_methods = 0
	with redis_client(timeout=5) as redis:
		methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
		for method_name in methods:
			deprecated_methods += 1
			method_name = method_name.decode("utf-8")
			calls = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:count"))
			clients = decode_redis_result(redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:clients"))
			last_call = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:last_call"))
			result.add_partial_result(
				PartialCheckResult(
					check_id=f"deprecated_calls:{method_name}",
					check_status=CheckStatus.WARNING,
					message=f"Deprecated method '{method_name}' was called {calls} times.",
					details={"method": method_name, "calls": calls, "last_call": last_call, "clients": clients},
				)
			)
	if deprecated_methods:
		result.message = f"Use of {deprecated_methods} deprecated methods found."
	return result


def check_opsi_packages() -> CheckResult:  # pylint: disable=too-many-locals,too-many-branches
	result = CheckResult(check_id="opsi_packages", check_name="OPSI packages", check_description="Check opsi package versions")
	try:
		res = requests.get(f"{OPSI_REPO}/{OPSI_PACKAGES_PATH}", timeout=5)
	except requests.RequestException as err:
		result.check_status = CheckStatus.ERROR
		result.message = f"Failed to get package info from repository '{OPSI_REPO}/{OPSI_PACKAGES_PATH}': {err}"
		return result

	result.message = "All packages are up to date."
	available_packages = OPSI_PACKAGES
	backend = get_backend()

	not_installed = 0
	outdated = 0
	for filename in findall(r'<a href="(?P<file>[\w\d._-]+\.opsi)">(?P=file)</a>', res.text):
		product_id, available_version = split_name_and_version(filename)
		if product_id in available_packages:  # pylint: disable=loop-invariant-statement
			available_packages[product_id] = available_version  # pylint: disable=loop-invariant-statement

	depots = backend.host_getIdents(type="OpsiDepotserver")  # pylint: disable=no-member
	for depot_id in depots:
		for product_id, available_version in available_packages.items():
			partial_result = PartialCheckResult(
				check_id=f"opsi_packages:{depot_id}:{product_id}", details={"depot_id": depot_id, "product_id": product_id}
			)
			try:  # pylint: disable=loop-try-except-usage
				product_on_depot = backend.productOnDepot_getObjects(productId=product_id, depotId=depot_id)[0]  # pylint: disable=no-member
			except IndexError as error:
				not_installed = not_installed + 1
				logger.debug(error)
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"Package '{product_id}' is not installed."
				result.add_partial_result(partial_result)
				continue

			if parse_version(available_version) > parse_version(f"{product_on_depot.productVersion}-{product_on_depot.packageVersion}"):
				outdated = outdated + 1
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = (
					f"Package '{product_id}' is outdated. Installed version: {product_on_depot.productVersion}-{product_on_depot.packageVersion}"
					f"- available version: {available_version}"
				)
			else:
				partial_result.check_status = CheckStatus.OK
				partial_result.message = f"Installed version: {product_on_depot.productVersion}-{product_on_depot.packageVersion}."
			result.add_partial_result(partial_result)

	result.details = {"packages": len(OPSI_PACKAGES.keys()), "depots": len(depots), "not_installed": not_installed, "outdated": outdated}
	if not_installed > 0 or outdated > 0:
		result.message = (
			f"Out of {len(OPSI_PACKAGES.keys())} packages on {len(depots)} depots checked, "
			f"{not_installed} are not installed and {outdated} are out of date."
		)
	return result


def check_opsi_licenses() -> CheckResult:  # pylint: disable=unused-argument
	result = CheckResult(check_id="opsi_licenses", check_name="OPSI licenses", check_description="Check opsi licensing state")
	backend = get_backend()
	licensing_info = backend.backend_getLicensingInfo()  # pylint: disable=no-member
	result.details = {"client_numbers": licensing_info["client_numbers"]}
	for module_id, module_data in licensing_info.get("modules", {}).items():  # pylint: disable=use-dict-comprehension
		if module_data["state"] == "free":
			continue

		partial_result = PartialCheckResult(
			check_id=f"opsi_licenses:{module_id}",
			details={"module_id": module_id, "state": module_data["state"], "client_number": module_data["client_number"]},
		)
		if module_data["state"] == "close_to_limit":
			partial_result.check_status = CheckStatus.WARNING
			partial_result.message = f"License for module '{module_id}' is close to the limit."
		elif module_data["state"] == "over_limit":
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"License for module '{module_id}' is over the limit."
		else:
			partial_result.check_status = CheckStatus.OK
			partial_result.message = f"License for module '{module_id}' is valid."
		result.add_partial_result(partial_result)
	return result


def split_name_and_version(filename: str) -> tuple:
	match = re.search(r"(?P<name>[\w_-]+)_(?P<version>.+-.+)\.opsi", filename)
	if not match:
		raise ValueError(f"Unable to split software name and version from {filename}")
	return (match.group("name"), match.group("version"))


# check result print functions


def console_print(msg: str, console: Console, style: str = "", indent_level: int = 0) -> None:
	indent_size = 5
	console.print(Padding(f"{style}{msg}", (0, indent_size * indent_level)))  # pylint: disable=loop-global-usage


def print_check_result(check_result: CheckResult, console: Console) -> None:
	console_print(check_result.message, console, STYLES[check_result.check_status], 1)


def print_check_deprecated_calls_result(check_result: CheckResult, console: Console) -> None:
	style = STYLES[check_result.check_status]

	console_print(check_result.message, console, style, 1)
	for partial_result in check_result.partial_results:
		details = partial_result.details
		console_print(partial_result.message, console, style, 1)
		console_print("The method was called from:", console, style, 1)
		for client in details["clients"]:  # pylint: disable=loop-invariant-statement
			console_print(f"- {client}", console, style, 2)  # pylint: disable=loop-invariant-statement
		console_print(f"Last call was {details['last_call']}", console, style, 1)


def print_check_opsi_licenses_results(check_result: CheckResult, console: Console) -> None:
	style = STYLES[check_result.check_status]
	console_print(f"Active clients: {check_result.details['client_numbers']['all']}", console, indent_level=1)
	for partial_result in check_result.partial_results:
		console_print(f"{partial_result.details['module_id']}:", console, indent_level=1)
		console_print(f"- {partial_result.message}", console, style, 2)  # pylint: disable=loop-invariant-statement
		console_print(f"- Client limit: {partial_result.details['client_number']}", console, style, 2)


def print_check_opsi_packages_result(check_result: CheckResult, console: Console) -> None:
	style = STYLES[check_result.check_status]
	console_print(check_result.message, console, style, 1)

	partial_result_depot_id: dict[str, list[PartialCheckResult]] = defaultdict(list)
	for partial_result in check_result.partial_results:  # pylint: disable=use-list-copy
		partial_result_depot_id[partial_result.details["depot_id"]].append(partial_result)

	for depot_id, partial_results in partial_result_depot_id.items():
		console_print(f"{depot_id}:", console, indent_level=1)
		for partial_result in partial_results:
			console_print(f"{partial_result.message}", console, style, 2)  # pylint: disable=loop-invariant-statement


def print_check_system_packages_result(check_result: CheckResult, console: Console) -> None:
	styles = STYLES
	for partial_result in check_result.partial_results:
		console_print(partial_result.message, console, styles[partial_result.check_status], 1)
