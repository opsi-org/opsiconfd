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
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from re import findall
from subprocess import run
from typing import Any, Generator, Iterator

import psutil
import requests
from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import]
from OPSI.Util import compareVersions  # type: ignore[import]
from opsicommon.logging.constants import (
	LEVEL_TO_NAME,
	LOG_DEBUG,
	LOG_TRACE,
	OPSI_LEVEL_TO_LEVEL,
)
from opsicommon.system.info import linux_distro_id_like_contains  # type: ignore[import]
from redis.exceptions import ConnectionError as RedisConnectionError
from requests import get
from requests.exceptions import ConnectionError as RequestConnectionError
from requests.exceptions import ConnectTimeout
from rich.console import Console
from rich.padding import Padding
from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd import __version__
from opsiconfd.backend import get_unprotected_backend
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.config import DEPOT_DIR, REPOSITORY_DIR, WORKBENCH_DIR, config
from opsiconfd.logging import logger
from opsiconfd.redis import decode_redis_result, redis_client

REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/stable/Debian_11/"
OPSI_REPO = "https://download.uib.de"
OPSI_PACKAGES_PATH = "4.2/stable/packages/windows/localboot/"
CHECK_SYSTEM_PACKAGES = ("opsiconfd", "opsi-utils", "opsipxeconfd")
CHECK_OPSI_PACKAGES = ("opsi-script", "opsi-client-agent")
OPSI_PACKAGES_MIN_VERSIONS_UPGRADE = {"opsi-script": "4.12.7.5-3", "opsi-client-agent": "4.2.0.43-3"}


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
	upgrade_issue: str | None = None


@dataclass(slots=True, kw_only=True)
class CheckResult(PartialCheckResult):
	partial_results: list[PartialCheckResult] = field(default_factory=list)

	def add_partial_result(self, partial_result: PartialCheckResult) -> None:
		self.partial_results.append(partial_result)
		if partial_result.check_status == CheckStatus.ERROR:
			self.check_status = CheckStatus.ERROR
		if partial_result.check_status == CheckStatus.WARNING and self.check_status != CheckStatus.ERROR:
			self.check_status = CheckStatus.WARNING
		if partial_result.upgrade_issue:
			if not self.upgrade_issue or compareVersions(partial_result.upgrade_issue, "<", self.upgrade_issue):
				self.upgrade_issue = partial_result.upgrade_issue


STYLES = {CheckStatus.OK: "bold green", CheckStatus.WARNING: "bold yellow", CheckStatus.ERROR: "bold red"}


def health_check() -> Iterator[CheckResult]:
	for check in (
		check_opsiconfd_config,
		check_opsi_config,
		check_disk_usage,
		check_depotservers,
		check_system_packages,
		check_product_on_depots,
		check_product_on_clients,
		check_redis,
		check_mysql,
		check_opsi_licenses,
		check_deprecated_calls,
	):
		yield check()


@contextmanager
def exc_to_result(result: CheckResult) -> Generator[None, None, None]:
	try:
		yield
	except (OperationalError, MySQLdbOperationalError) as err:  # pylint: disable=broad-except
		result.check_status = CheckStatus.ERROR
		error_str = str(err).split("\n", 1)[0]
		match = re.search(r"\((\d+),\s+(\S.*)\)", error_str)
		if match:
			error_str = match.group(1) + " - " + match.group(2).strip("'").replace("\\'", "'")
		result.message = error_str
	except RedisConnectionError as err:
		result.check_status = CheckStatus.ERROR
		result.message = f"Cannot connect to Redis: {err}"
	except Exception as err:  # pylint: disable=broad-except
		result.check_status = CheckStatus.ERROR
		result.message = str(err)


def get_repo_versions() -> dict[str, str | None]:
	url = REPO_URL
	packages = CHECK_SYSTEM_PACKAGES
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
		match = re.search(f"{package}_(.+?).tar.gz", repo_data.text)
		if match:
			version = match.group(1)
			repo_versions[package] = version
			logger.debug("Available version for %s: %s", package, version)
	return repo_versions


def get_disk_mountpoints() -> set:
	partitions = psutil.disk_partitions()
	check_mountpoints = set()
	var_added = False
	for mountpoint in sorted([p.mountpoint for p in partitions if p.fstype], reverse=True):
		if mountpoint in ("/", "/tmp") or mountpoint.startswith("/var/lib/opsi/"):
			check_mountpoints.add(mountpoint)
		elif mountpoint in ("/var", "/var/lib", "/var/lib/opsi") and not var_added:
			check_mountpoints.add(mountpoint)
			var_added = True
	return check_mountpoints


def check_disk_usage() -> CheckResult:
	result = CheckResult(
		check_id="disk_usage",
		check_name="Disk usage",
		check_description="Check disk usage",
		message="Sufficient free space on all file systems.",
	)
	with exc_to_result(result):
		check_mountpoints = get_disk_mountpoints()

		count = 0
		for mountpoint in check_mountpoints:
			usage = psutil.disk_usage(mountpoint)
			percent_free = usage.free * 100 / usage.total
			free_gb = usage.free / 1_000_000_000
			check_status = CheckStatus.OK
			if free_gb < 7.5:
				count += 1
				check_status = CheckStatus.ERROR
			elif free_gb < 15:
				count += 1
				check_status = CheckStatus.WARNING
			partial_result = PartialCheckResult(
				check_id=f"disk_usage:{mountpoint}",
				check_name=f"Disk usage on filesystem {mountpoint!r}",
				check_status=check_status,
				message=(
					f"{'Sufficient' if check_status == CheckStatus.OK else 'Insufficient'}"
					f" free space of {free_gb:0.2f} GB ({percent_free:0.2f} %) on {mountpoint!r}"
				),
				details={"mountpoint": mountpoint, "total": usage.total, "used": usage.used, "free": usage.free},
			)
			result.add_partial_result(partial_result)

		if result.check_status != CheckStatus.OK:
			result.message = f"Insufficient free space on {count} file system{'s' if count > 1 else ''}."
	return result


def check_depotservers() -> CheckResult:
	result = CheckResult(
		check_id="depotservers",
		check_name="Depotserver check",
		check_description="Check configuration and state of depotservers",
		message="No problems found with the depot servers.",
	)
	with exc_to_result(result):
		backend = get_unprotected_backend()
		issues = 0
		for depot in backend.host_getObjects(type="OpsiDepotserver"):  # pylint: disable=no-member
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
				partial_result.upgrade_issue = "4.3"
				partial_result.message = (
					f"The local depot path is no longer configurable in version 4.3 and is set to {path!r} on depot {depot.id!r}."
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
				partial_result.upgrade_issue = "4.3"
				partial_result.message = (
					f"The local repository path is no longer configurable in version 4.3 and is set to {path!r} on depot {depot.id!r}."
				)
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
				partial_result.upgrade_issue = "4.3"
				partial_result.message = (
					f"The local workbench path is no longer configurable in version 4.3 and is set to {path!r} on depot {depot.id!r}."
				)
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
	with exc_to_result(result):
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


def get_installed_packages(packages: dict | None = None) -> dict:
	installed_versions: dict[str, str] = {}
	if linux_distro_id_like_contains(("sles", "rhel")):
		cmd = ["yum", "list", "installed"]
		regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+).*$")
		res = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
		for line in res.split("\n"):
			match = regex.search(line)
			if not match:
				continue
			p_name = match.group(1).split(".")[0]
			if not packages:
				if p_name.startswith("opsi"):
					logger.info("Package '%s' found: version '%s'", p_name, match.group(2))
					installed_versions[p_name] = match.group(2)
			else:
				if p_name in packages:
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
			if not packages:
				if p_name.startswith("opsi"):
					logger.info("Package '%s' found: version '%s'", p_name, match.group(3))
					installed_versions[p_name] = match.group(3)
			else:
				if p_name in packages:
					logger.info("Package '%s' found: version '%s'", p_name, match.group(3))
					installed_versions[p_name] = match.group(3)
	else:
		cmd = ["dpkg", "-l"]
		regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*$")
		res = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
		for line in res.split("\n"):
			match = regex.search(line)
			if not match or match.group(1) != "ii":
				continue
			p_name = match.group(2)
			if not packages:
				if p_name.startswith("opsi"):
					logger.info("Package '%s' found: version '%s'", p_name, match.group(3))
					installed_versions[p_name] = match.group(3)
			else:
				if p_name in packages:
					logger.info("Package '%s' found: version '%s'", p_name, match.group(3))
					installed_versions[p_name] = match.group(3)
	return installed_versions


def check_system_packages() -> CheckResult:  # pylint: disable=too-many-branches, too-many-statements, too-many-locals
	result = CheckResult(
		check_id="system_packages",
		check_name="System packages",
		check_description="Check system package versions",
		message="All packages are up to date.",
	)
	with exc_to_result(result):
		repo_versions = get_repo_versions()
		installed_versions: dict[str, str] = {}
		try:
			installed_versions = get_installed_packages(repo_versions)
		except RuntimeError as err:
			error = f"Could not get package versions from system: {err}"
			logger.error(error)
			result.check_status = CheckStatus.ERROR
			result.message = error
			return result

		logger.info("Installed packages: %s", installed_versions)

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
				partial_result.message = f"Package {package!r} is not installed."
				partial_result.upgrade_issue = __version__
				not_installed = not_installed + 1
			elif compareVersions(available_version or "0", ">", details["version"]):
				outdated = outdated + 1
				partial_result.check_status = CheckStatus.WARNING
				partial_result.message = (
					f"Package {package!r} is out of date. "
					f"Installed version {details['version']!r} < available version {available_version!r}"
				)
				details["outdated"] = True
			else:
				partial_result.check_status = CheckStatus.OK
				partial_result.message = f"Package {package!r} is up to date. Installed version: {details['version']!r}"
			result.add_partial_result(partial_result)

		result.details = {"packages": len(repo_versions.keys()), "not_installed": not_installed, "outdated": outdated}
		if not_installed > 0 or outdated > 0:
			result.message = (
				f"Out of {len(repo_versions.keys())} packages checked, {not_installed} are not installed and {outdated} are out of date."
			)
	return result


def check_redis() -> CheckResult:
	result = CheckResult(
		check_id="redis",
		check_name="Redis server",
		check_description="Check Redis server state",
		details={"connection": False, "timeseries": False},
	)
	with exc_to_result(result):
		with redis_client(timeout=5, test_connection=True) as redis:
			result.details["connection"] = True
			redis_info = decode_redis_result(redis.execute_command("INFO"))
			logger.debug("Redis info: %s", redis_info)
			modules = [module["name"] for module in redis_info["modules"]]
			if "timeseries" not in modules:
				result.details["timeseries"] = False
				result.check_status = CheckStatus.ERROR
				result.message = "RedisTimeSeries not loaded."
			else:
				result.check_status = CheckStatus.OK
				result.message = "Redis is running and RedisTimeSeries is loaded."

	return result


def check_mysql() -> CheckResult:
	result = CheckResult(check_id="mysql", check_name="MySQL server", check_description="Check MySQL server state")
	with exc_to_result(result):
		mysql = MySQLConnection()
		with mysql.connection():
			result.check_status = CheckStatus.OK
			result.message = "Connection to MySQL is working."

	return result


def check_deprecated_calls() -> CheckResult:
	result = CheckResult(
		check_id="deprecated_calls",
		check_name="Deprecated RPCs",
		check_description="Check use of deprecated RPC methods",
		message="No deprecated method calls found.",
	)
	with exc_to_result(result):
		backend = get_unprotected_backend()
		redis_prefix_stats = config.redis_key("stats")
		deprecated_methods = 0
		with redis_client(timeout=5) as redis:
			methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
			for method_name in methods:
				deprecated_methods += 1
				method_name = method_name.decode("utf-8")
				interface = backend.get_method_interface(method_name)
				calls = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:count"))
				applications = decode_redis_result(redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:clients"))
				last_call = decode_redis_result(redis.get(f"{redis_prefix_stats}:rpcs:deprecated:{method_name}:last_call"))
				last_call_dt = datetime.fromisoformat(last_call.replace("Z", "")).astimezone(timezone.utc)
				last_call = last_call_dt.strftime("%Y-%m-%d %H:%M:%S")
				message = f"Deprecated method {method_name!r} was called {calls} times.\n"
				if interface and interface.drop_version:
					message += f"The method will be dropped with opsiconfd version {interface.drop_version}.\n"
				message += f"Last call was {last_call}\nThe method was called from the following applications:\n"
				message += "\n".join([f"- {app}" for app in applications])
				result.add_partial_result(
					PartialCheckResult(
						check_id=f"deprecated_calls:{method_name}",
						check_name=f"Deprecated method {method_name!r}",
						check_status=CheckStatus.WARNING,
						message=message,
						upgrade_issue=interface.drop_version if interface else None,
						details={
							"method": method_name,
							"calls": calls,
							"last_call": last_call,
							"applications": list(applications),
							"drop_version": interface.drop_version if interface else None,
						},
					)
				)
		if deprecated_methods:
			result.message = f"Use of {deprecated_methods} deprecated methods found."
	return result


def check_product_on_depots() -> CheckResult:  # pylint: disable=too-many-locals,too-many-branches
	result = CheckResult(
		check_id="product_on_depots", check_name="Products on depots", check_description="Check opsi package versions on depots"
	)
	with exc_to_result(result):
		try:
			res = requests.get(f"{OPSI_REPO}/{OPSI_PACKAGES_PATH}", timeout=5)
		except requests.RequestException as err:
			result.check_status = CheckStatus.ERROR
			result.message = f"Failed to get package info from repository '{OPSI_REPO}/{OPSI_PACKAGES_PATH}': {err}"
			return result

		result.message = "All important products are up to date on all depots."
		available_packages = {p: "0.0" for p in CHECK_OPSI_PACKAGES}
		backend = get_unprotected_backend()

		not_installed = 0
		outdated = 0
		for filename in findall(r'<a href="(?P<file>[\w\d._-]+\.opsi)">(?P=file)</a>', res.text):
			product_id, available_version = split_name_and_version(filename)
			if product_id in available_packages:
				available_packages[product_id] = available_version

		depots = backend.host_getIdents(type="OpsiDepotserver")  # pylint: disable=no-member
		for depot_id in depots:
			for product_id, available_version in available_packages.items():
				partial_result = PartialCheckResult(
					check_id=f"product_on_depots:{depot_id}:{product_id}",
					check_name=f"Product {product_id!r} on {depot_id!r}",
					details={"depot_id": depot_id, "product_id": product_id},
				)
				try:
					product_on_depot = backend.productOnDepot_getObjects(productId=product_id, depotId=depot_id)[0]
				except IndexError as error:
					not_installed = not_installed + 1
					logger.debug(error)
					partial_result.check_status = CheckStatus.ERROR
					partial_result.message = f"Product {product_id!r} is not installed on depot {depot_id!r}."
					partial_result.upgrade_issue = "4.3"
					result.add_partial_result(partial_result)
					continue

				product_version_on_depot = f"{product_on_depot.productVersion}-{product_on_depot.packageVersion}"
				partial_result.details["version"] = product_version_on_depot
				partial_result.details["available_version"] = available_version

				if compareVersions(available_version, ">", product_version_on_depot):
					outdated = outdated + 1
					partial_result.check_status = CheckStatus.ERROR
					partial_result.message = (
						f"Product {product_id!r} is outdated on depot {depot_id!r}. Installed version {product_version_on_depot!r}"
						f" < available version {available_version!r}."
					)
				else:
					partial_result.check_status = CheckStatus.OK
					partial_result.message = (
						f"Installed version of product {product_id!r} on depot {depot_id!r} is {product_version_on_depot!r}."
					)

				min_version = OPSI_PACKAGES_MIN_VERSIONS_UPGRADE.get(product_id)
				if min_version and compareVersions(min_version, ">", product_version_on_depot):
					partial_result.upgrade_issue = "4.3"

				result.add_partial_result(partial_result)

		result.details = {
			"products": len(CHECK_OPSI_PACKAGES),
			"depots": len(depots),
			"not_installed": not_installed,
			"outdated": outdated,
		}
		if not_installed > 0 or outdated > 0:
			result.message = (
				f"Out of {len(CHECK_OPSI_PACKAGES)} products on {len(depots)} depots checked, "
				f"{not_installed} are not installed and {outdated} are out of date."
			)
	return result


def check_product_on_clients() -> CheckResult:  # pylint: disable=too-many-locals,too-many-branches
	result = CheckResult(
		check_id="product_on_clients", check_name="Products on clients", check_description="Check opsi package versions on clients"
	)
	with exc_to_result(result):
		result.message = "All important products are up to date on all clients."
		backend = get_unprotected_backend()
		now = datetime.now()
		client_ids = [
			host.id
			for host in backend.host_getObjects(attributes=["id", "lastSeen"], type="OpsiClient")
			if host.lastSeen and (now - datetime.fromisoformat(host.lastSeen)).days < 90
		]
		if not client_ids:
			return result

		outdated_client_ids = set()
		for product_id, min_version in OPSI_PACKAGES_MIN_VERSIONS_UPGRADE.items():
			for product_on_client in backend.productOnClient_getObjects(
				attributes=["productVersion", "packageVersion"],
				clientId=client_ids,
				productId=product_id,
				installationStatus="installed",
			):
				version = f"{product_on_client.productVersion}-{product_on_client.packageVersion}"
				if compareVersions(version, ">=", min_version):
					continue
				client_id = product_on_client.clientId
				partial_result = PartialCheckResult(
					check_status=CheckStatus.ERROR,
					check_id=f"product_on_clients:{client_id}:{product_id}",
					check_name=f"Product {product_id!r} on {client_id!r}",
					message=(
						f"Product {product_id!r} is outdated on client {client_id!r}. "
						f"Installed version {version!r} < recommended version {min_version!r}"
					),
					details={"client_id": client_id, "product_id": product_id, "version": version},
					upgrade_issue="4.3",
				)
				outdated_client_ids.add(client_id)
				result.add_partial_result(partial_result)

		result.details = {"outdated_clients": len(outdated_client_ids)}
		if outdated_client_ids:
			result.message = (
				f"There are {len(outdated_client_ids)} active clients (last seen < 90 days) where important products are out of date."
			)
	return result


def check_opsi_licenses() -> CheckResult:  # pylint: disable=unused-argument
	result = CheckResult(check_id="opsi_licenses", check_name="OPSI licenses", check_description="Check opsi licensing state")
	with exc_to_result(result):
		backend = get_unprotected_backend()
		licensing_info = backend.backend_getLicensingInfo()  # pylint: disable=no-member
		result.message = f"{licensing_info['client_numbers']['all']} active clients"
		result.details = {"client_numbers": licensing_info["client_numbers"]}
		for module_id, module_data in licensing_info.get("modules", {}).items():
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


def check_opsi_config() -> CheckResult:  # pylint: disable=unused-argument
	result = CheckResult(
		check_id="opsi_config",
		check_name="OPSI Configuration",
		check_description="Check opsi configuration state",
		message="No issues found in the opsi configuration.",
	)
	with exc_to_result(result):
		backend = get_unprotected_backend()
		check_configs: dict[str, Any] = {"opsiclientd.global.verify_server_cert": [True]}
		count = 0
		for key, default_value in check_configs.items():
			partial_result = PartialCheckResult(
				check_id=f"opsi_config:{key}",
				check_name=f"OPSI Configuration {key}",
				details={"config_id": key, "deafult_value": default_value},
			)
			conf = backend.config_getObjects(id=key)
			try:
				if conf[0].defaultValues == default_value:
					partial_result.check_status = CheckStatus.OK
					partial_result.message = f"Configuration {key} is set to default."
				else:
					partial_result.check_status = CheckStatus.WARNING
					partial_result.message = f"Configuration {key} is set to {conf[0].defaultValues} - default is {default_value}."
					partial_result.upgrade_issue = "4.3"
					count = count + 1
				partial_result.details["value"] = conf[0].defaultValues
				result.add_partial_result(partial_result)
			except IndexError:
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"Configuration {key} does not exist."
				partial_result.details["value"] = None
				result.add_partial_result(partial_result)
				partial_result.upgrade_issue = "4.3"
				count = count + 1
				continue
		if count > 0:
			result.message = f"{count} issues found in the opsi configuration."
	return result


def split_name_and_version(filename: str) -> tuple:
	match = re.search(r"(?P<name>[\w_-]+)_(?P<version>.+-.+)\.opsi", filename)
	if not match:
		raise ValueError(f"Unable to split software name and version from {filename}")
	return (match.group("name"), match.group("version"))


def console_print_message(check_result: CheckResult | PartialCheckResult, console: Console, indent: int = 0) -> None:
	style = STYLES[check_result.check_status]
	status = check_result.check_status.upper()
	msg_ident = " " * (len(status) + 3)
	message = "\n".join([f"{msg_ident if idx > 0 else ''}{line}" for idx, line in enumerate(check_result.message.split("\n"))])
	console.print(Padding(f"[{style}]{status}[/{style}] - {message}", (0, indent)))


def process_check_result(
	result: CheckResult,
	console: Console,
	check_version: str | None = None,
	detailed: bool = False,
	summary: dict[CheckStatus, int] | None = None,
) -> None:
	status = result.check_status
	message = result.message
	partial_results = []
	for pres in result.partial_results:
		if check_version and (not pres.upgrade_issue or compareVersions(pres.upgrade_issue, ">", check_version)):
			continue
		partial_results.append(pres)
		if summary:
			summary[pres.check_status] += 1

	if check_version:
		if partial_results:
			status = CheckStatus.ERROR
			message = f"{len(partial_results)} upgrade issues"
		else:
			status = CheckStatus.OK
			message = "No upgrade issues"
			if not detailed:
				return

	style = STYLES[status]
	console.print(f"[{style}]●[/{style}] [b]{result.check_name}[/b]: [{style}]{status.upper()}[/{style}]")
	console.print(Padding(f"[{style}]➔[/{style}] [b]{message}[/b]", (0, 3)))

	if not detailed:
		return

	if partial_results:
		console.print("")
	for partial_result in partial_results:
		console_print_message(partial_result, console, 3)
	console.print("")


def console_health_check() -> int:  # pylint: disable=too-many-branches
	summary = {CheckStatus.OK: 0, CheckStatus.WARNING: 0, CheckStatus.ERROR: 0}
	check_version = None
	if config.upgrade_check:
		if config.upgrade_check is True:
			check_version = "1000"
		else:
			check_version = config.upgrade_check

	console = Console(log_time=False)
	styles = STYLES
	with console.status("Health check running", spinner="arrow3"):
		for result in health_check():
			process_check_result(result=result, console=console, check_version=check_version, detailed=config.detailed, summary=summary)
	status = CheckStatus.OK
	return_code = 0
	if summary[CheckStatus.ERROR]:
		status = CheckStatus.ERROR
		return_code = 1
	elif summary[CheckStatus.WARNING]:
		status = CheckStatus.WARNING
		return_code = 2

	style = styles[status]
	res = f"Check completed with {summary[CheckStatus.ERROR]} errors and {summary[CheckStatus.WARNING]} warnings."
	console.print(f"[{style}]{status.upper()}[/{style}]: [b]{res}[/b]")
	return return_code
