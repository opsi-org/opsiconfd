# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from re import findall
from subprocess import run
from typing import Any

import requests
from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import]
from opsicommon.logging.constants import (
	LEVEL_TO_NAME,
	LOG_DEBUG,
	LOG_TRACE,
	OPSI_LEVEL_TO_LEVEL,
)
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
from opsiconfd.config import DEPOT_DIR, REPOSITORY_DIR, WORKBENCH_DIR, config
from opsiconfd.logging import logger
from opsiconfd.redis import decode_redis_result, redis_client

REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/stable/Debian_11/"
PACKAGES = ("opsiconfd", "opsi-utils", "opsipxeconfd")
OPSI_REPO = "https://download.uib.de"
OPSI_PACKAGES_PATH = "4.2/stable/packages/windows/localboot/"
OPSI_PACKAGES = {"opsi-script": "0.0", "opsi-client-agent": "0.0"}


class CheckStatus(StrEnum):
	OK = "ok"
	WARNING = "warning"
	ERROR = "error"


@dataclass(slots=True, kw_only=True)
class PartialCheckResult:
	check_id: str
	check_name: str = ""
	check_description: str = ""
	check_status: CheckStatus = CheckStatus.OK
	message: str = ""
	details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, kw_only=True)
class CheckResult(PartialCheckResult):
	partial_results: list[PartialCheckResult] = field(default_factory=list)

	def add_partial_result(self, partial_result: PartialCheckResult) -> None:
		self.partial_results.append(partial_result)
		if partial_result.check_status == CheckStatus.ERROR:
			self.check_status = CheckStatus.ERROR
		if partial_result.check_status == CheckStatus.WARNING and self.check_status != CheckStatus.ERROR:
			self.check_status = CheckStatus.WARNING


STYLES = {CheckStatus.OK: "[bold green]", CheckStatus.WARNING: "[bold yellow]", CheckStatus.ERROR: "[bold red]"}


def health_check() -> list[CheckResult]:
	return [
		check_opsiconfd_config(),
		check_depotservers(),
		check_system_packages(),
		check_opsi_packages(),
		check_redis(),
		check_mysql(),
		check_opsi_licenses(),
		check_deprecated_calls(),
	]


def console_health_check() -> int:
	console = Console(log_time=False)
	checks = (
		(check_opsiconfd_config, print_check_result),
		(check_depotservers, print_check_result),
		(check_system_packages, print_check_result),
		(check_opsi_packages, print_check_result),
		(check_redis, print_check_result),
		(check_mysql, print_check_result),
		(check_opsi_licenses, print_check_result),
		(check_deprecated_calls, print_check_result),
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


def check_depotservers() -> CheckResult:
	result = CheckResult(
		check_id="depotservers",
		check_name="Depotserver check",
		check_description="Checks configuration and state of depotservers",
		message="No problems found with the depot servers.",
	)
	backend = get_unprotected_backend()
	issues = 0
	for depot in backend.host_getObjects(type="OpsiDepotserver"):
		path = (depot.depotLocalUrl or "").removeprefix("file://").rstrip("/")
		partial_result = PartialCheckResult(
			check_id=f"depotservers:{depot.id}:depot_path",
			check_name=f"Depotserver depot_path on {depot.id!r}",
			message="The configured depot path corresponds to the default.",
			details={"path": path},
		)
		if path != DEPOT_DIR:
			issues += 1
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = (
				f"The local depot path is no longer configurable and is set to {DEPOT_DIR}."  # pylint: disable=loop-invariant-statement
			)
		result.add_partial_result(partial_result)

		path = (depot.repositoryLocalUrl or "").removeprefix("file://").rstrip("/")
		partial_result = PartialCheckResult(
			check_id=f"depotservers:{depot.id}:repository_path",
			check_name=f"Depotserver repository_path on {depot.id!r}",
			message="The configured repository path corresponds to the default.",
			details={"path": path},
		)
		if path != REPOSITORY_DIR:
			issues += 1
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"The local repository path is no longer configurable and is set to {REPOSITORY_DIR}."  # pylint: disable=loop-invariant-statement
		result.add_partial_result(partial_result)

		path = (depot.workbenchLocalUrl or "").removeprefix("file://").rstrip("/")
		partial_result = PartialCheckResult(
			check_id=f"depotservers:{depot.id}:workbench_path",
			check_name=f"Depotserver workbench_path on {depot.id!r}",
			message="The configured workbench path corresponds to the default.",
			details={"path": path},
		)
		if path != WORKBENCH_DIR:
			issues += 1
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"The path to the workbench directory is no longer configurable and is set to {WORKBENCH_DIR}."  # pylint: disable=loop-invariant-statement
		result.add_partial_result(partial_result)

	if issues > 0:
		result.message = f"{issues} issues found with the depot servers."

	return result


def check_opsiconfd_config() -> CheckResult:
	result = CheckResult(
		check_id="opsiconfd_config",
		check_name="Opsiconfd config",
		check_description="Check opsiconfd configuration",
		message="No issues found in the configuration.",
	)
	issues = 0
	for attribute in "log-level-stderr", "log-level-file", "log-level":
		value = getattr(config, attribute.replace("-", "_"))
		level_name = LEVEL_TO_NAME[OPSI_LEVEL_TO_LEVEL[value]]
		partial_result = PartialCheckResult(
			check_id=f"opsiconfd_config:{attribute}",
			check_name=f"Config {attribute}",
			message=f"Log level {level_name} is suitable for productive use.",
			details={"config": attribute, "value": value},
		)
		if value >= LOG_TRACE:
			issues += 1
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"Log level {level_name} is much to high for productive use."
		elif value >= LOG_DEBUG:
			issues += 1
			partial_result.check_status = CheckStatus.WARNING
			partial_result.message = f"Log level {level_name} is to high for productive use."
		result.add_partial_result(partial_result)

	partial_result = PartialCheckResult(
		check_id="opsiconfd_config:debug-options",
		check_name="Config debug-options",
		message="No debug options are set.",
		details={"config": "debug-options", "value": config.debug_options},
	)
	if config.debug_options:
		issues += 1
		partial_result.check_status = CheckStatus.ERROR
		partial_result.message = f"The following debug options are set: {', '.join(config.debug_options)}."
	result.add_partial_result(partial_result)

	partial_result = PartialCheckResult(
		check_id="opsiconfd_config:profiler",
		check_name="Config profiler",
		message="Profiler is not enabled.",
		details={"config": "profiler", "value": config.profiler},
	)
	if config.profiler:
		issues += 1
		partial_result.check_status = CheckStatus.ERROR
		partial_result.message = "Profiler is enabled."
	result.add_partial_result(partial_result)

	partial_result = PartialCheckResult(
		check_id="opsiconfd_config:run-as-user",
		check_name="Config run-as-user",
		message=f"Opsiconfd is runnning as user {config.run_as_user}.",
		details={"config": "profiler", "value": config.run_as_user},
	)
	if config.run_as_user == "root":
		issues += 1
		partial_result.check_status = CheckStatus.ERROR
	result.add_partial_result(partial_result)

	if issues > 0:
		result.message = f"{issues} issues found in the configuration."

	return result


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
		if linux_distro_id_like_contains(("sles", "rhel")):
			cmd = ["yum", "list", "installed"]
			regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+).*$")
			res = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
			for line in res.split("\n"):
				match = regex.search(line)
				if not match:
					continue
				p_name = match.group(1).split(".")[0]
				if p_name in repo_versions:
					logger.info("Package '%s' found: version '%s'", p_name, match.group(2))
					installed_versions[p_name] = match.group(2)
		elif linux_distro_id_like_contains("opensuse"):
			cmd = ["zypper", "search", "-is", "opsi*"]
			regex = re.compile(r"^[^S]\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+).*$")
			res = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
			for line in res.split("\n"):
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
			res = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
			for line in res.split("\n"):
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
		partial_result = PartialCheckResult(
			check_id=f"system_packages:{package}", check_name=f"System package {package!r}", details=details
		)
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
	redis_prefix_stats = config.redis_key("stats")
	deprecated_methods = 0
	with redis_client(timeout=5) as redis:
		methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
		for method_name in methods:
			deprecated_methods += 1
			method_name = method_name.decode("utf-8")
			calls = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:count"))
			applications = decode_redis_result(redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:clients"))
			last_call = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:last_call"))
			message = (
				f"Deprecated method {method_name!r} was called {calls} times.\n"
				f"Last call was {last_call}\n"
				"The method was called from the following applications:\n"
			)
			message += "\n".join([f"- {app}" for app in applications])  # pylint: disable=loop-invariant-statement
			result.add_partial_result(
				PartialCheckResult(
					check_id=f"deprecated_calls:{method_name}",
					check_name=f"Deprecated method {method_name!r}",
					check_status=CheckStatus.WARNING,
					message=message,
					details={"method": method_name, "calls": calls, "last_call": last_call, "applications": list(applications)},
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
	backend = get_unprotected_backend()

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
				check_id=f"opsi_packages:{depot_id}:{product_id}",
				check_name=f"OPSI package {product_id!r} on {depot_id!r}",
				details={"depot_id": depot_id, "product_id": product_id},
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
	backend = get_unprotected_backend()
	licensing_info = backend.backend_getLicensingInfo()  # pylint: disable=no-member
	result = CheckResult(
		check_id="opsi_licenses",
		check_name="OPSI licenses",
		check_description="Check opsi licensing state",
		message=f"{licensing_info['client_numbers']['all']} active clients",
		details={"client_numbers": licensing_info["client_numbers"]},
	)
	for module_id, module_data in licensing_info.get("modules", {}).items():  # pylint: disable=use-dict-comprehension
		if module_data["state"] == "free":
			continue

		partial_result = PartialCheckResult(
			check_id=f"opsi_licenses:{module_id}",
			check_name=f"OPSI license for module {module_id!r}",
			details={"module_id": module_id, "state": module_data["state"], "client_number": module_data["client_number"]},
		)
		if module_data["state"] == "close_to_limit":
			partial_result.check_status = CheckStatus.WARNING
			partial_result.message = f"License for module '{module_id}' is close to the limit of {module_data['client_number']}."
		elif module_data["state"] == "over_limit":
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"License for module '{module_id}' is over the limit of {module_data['client_number']}."
		else:
			partial_result.check_status = CheckStatus.OK
			partial_result.message = f"License for module '{module_id}' is below the limit of {module_data['client_number']}."
		result.add_partial_result(partial_result)

	if result.check_status == CheckStatus.OK:
		result.message += ", no licensing issues."
	else:
		result.message += ", licensing issues detected."
	return result


def split_name_and_version(filename: str) -> tuple:
	match = re.search(r"(?P<name>[\w_-]+)_(?P<version>.+-.+)\.opsi", filename)
	if not match:
		raise ValueError(f"Unable to split software name and version from {filename}")
	return (match.group("name"), match.group("version"))


def console_print(msg: str, console: Console, style: str = "", indent_level: int = 0) -> None:
	indent_size = 5
	console.print(Padding(f"{style}{msg}", (0, indent_size * indent_level)))  # pylint: disable=loop-global-usage


def print_check_result(check_result: CheckResult, console: Console) -> None:
	style = STYLES[check_result.check_status]
	console_print(check_result.message, console, style, 1)
	for partial_result in check_result.partial_results:
		console_print(partial_result.message, console, style, 1)
