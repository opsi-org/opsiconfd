# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
check tests
"""


import io
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable
from unittest import mock
from warnings import catch_warnings, simplefilter

import requests
from MySQLdb import OperationalError  # type: ignore[import]
from redis.exceptions import ConnectionError as RedisConnectionError
from rich.console import Console

from opsiconfd.check import (
	PACKAGES,
	CheckStatus,
	check_depotservers,
	check_deprecated_calls,
	check_mysql,
	check_opsi_licenses,
	check_opsiconfd_config,
	check_redis,
	check_system_packages,
	get_repo_versions,
	health_check,
	print_check_result,
)

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	get_config,
	sync_clean_redis,
	test_client,
)

DEPRECATED_METHOD = "getClientIds_list"


def captured_function_output(func: Callable, **kwargs: Any) -> str:
	captured_output = io.StringIO()
	sys.stdout = captured_output
	func(**kwargs)
	sys.stdout = sys.__stdout__
	return captured_output.getvalue()


def test_check_opsiconfd_config() -> None:
	with get_config({"log_level_stderr": 9, "debug_options": ["rpc-log", "asyncio"]}):
		result = check_opsiconfd_config()
		# print(result)
		ids_found = 0
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "2 issues found in the configuration."
		for partial_result in result.partial_results:
			assert partial_result.check_id.startswith("opsiconfd_config:")
			if partial_result.check_id == "opsiconfd_config:log-level-stderr":
				ids_found += 1
				assert partial_result.check_status == CheckStatus.ERROR
				assert partial_result.message == "Log level SECRET is much to high for productive use."
				assert partial_result.details == {'config': 'log-level-stderr', 'value': 9}
			elif partial_result.check_id == "opsiconfd_config:debug-options":
				assert partial_result.check_status == CheckStatus.ERROR
				assert partial_result.message == "The following debug options are set: rpc-log, asyncio."
				assert partial_result.details == {'config': 'debug-options', 'value':  ['rpc-log', 'asyncio']}  # pylint: disable=loop-invariant-statement
				ids_found += 1
		assert ids_found == 2


def test_check_depotservers(test_client: OpsiconfdTestClient) -> None:
	rpc = {
		"id": 1,
		"method": "host_createOpsiDepotserver",
		"params": [
			"depot1-check.opsi.org",
			None,
			"file:///some/path/to/depot",
			"smb://172.17.0.101/opsi_depot",
			None,
			"file:///some/path/to/repository",
			"webdavs://172.17.0.101:4447/repository",
		],
	}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	result = check_depotservers()
	assert result.check_status == CheckStatus.ERROR


def test_check_redis() -> None:
	console = Console(log_time=False)
	result = check_redis()
	captured_output = captured_function_output(print_check_result, check_result=result, console=console)
	assert "Redis is running and RedisTimeSeries is loaded." in captured_output
	assert result.check_status == "ok"


def test_check_redis_error() -> None:
	with mock.patch("opsiconfd.redis.get_redis_connection", side_effect=RedisConnectionError("Redis test error")):
		console = Console(log_time=False)
		result = check_redis()
		captured_output = captured_function_output(print_check_result, check_result=result, console=console)

		assert "Cannot connect to Redis" in captured_output
		assert result.check_status == "error"
		assert result.message == "Cannot connect to Redis: Redis test error"


def test_check_mysql() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False)
	result = check_mysql()
	captured_output = captured_function_output(print_check_result, check_result=result, console=console)

	assert "Connection to MySQL is working." in captured_output
	assert result.check_status == "ok"
	assert result.message == "Connection to MySQL is working."


def test_check_mysql_error() -> None:  # pylint: disable=redefined-outer-name
	with mock.patch(
		"opsiconfd.check.get_mysql", side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")')
	):
		console = Console(log_time=False)
		result = check_mysql()
		captured_output = captured_function_output(print_check_result, check_result=result, console=console)

		assert "Could not connect to MySQL:" in captured_output
		assert "(MySQLdb.OperationalError)" in captured_output
		assert result.check_status == "error"
		assert result.message == 'Could not connect to MySQL: (MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'


def test_get_repo_versions() -> None:
	result = get_repo_versions()
	for package in PACKAGES:
		assert package in result

	packages = ("opsiconfd", "opsi-utils")
	with open("tests/data/check/repo.html", "r", encoding="utf-8") as html_file:
		html_str = html_file.read()
	res = requests.Response()
	res.status_code = 200
	with mock.patch("requests.Response.text", mock.PropertyMock(return_value=html_str)):
		result = get_repo_versions()

	for package in packages:
		assert package in result
		if package == "opsiconfd":
			assert result[package] == "4.2.0.286-1"
		if package == "opsi-utils":
			assert result[package] == "4.2.0.183-1"


def test_check_system_packages_debian() -> None:  # pylint: disable=redefined-outer-name
	# test up to date packages - status sould be ok and output should be green
	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	console = Console(log_time=False, width=1000, highlight=False)
	dpkg_lines = [
		f"ii  {name}                         {version}                       amd64        Package description"
		for name, version in installed_versions.items()
	]

	class Proc:  # pylint: disable=too-few-public-methods
		stdout = "\n".join(dpkg_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"debian"})),
	):

		result = check_system_packages()
		captured_output = captured_function_output(print_check_result, check_result=result, console=console)

		for name, version in installed_versions.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK

		for partial_result in result.partial_results:
			assert partial_result.check_status == "ok"
			assert partial_result.message == (
				f"Package {partial_result.details['package']} is up to date. "
				f"Installed version: {partial_result.details['version']}"
			)

	# test outdated packages - status sould be warn and output sould be in yellow
	installed_versions = {"opsiconfd": "4.2.0.100-1", "opsi-utils": "4.2.0.100-1"}
	dpkg_lines = [
		f"ii  {name}                         {version}                       amd64        Package description"
		for name, version in installed_versions.items()
	]
	Proc.stdout = "\n".join(dpkg_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"debian"})),
	):
		result = check_system_packages()

		assert result.message == "Out of 2 packages checked, 0 are not installed and 2 are out of date."
		assert result.check_status == CheckStatus.WARNING
		for partial_result in result.partial_results:
			assert partial_result.check_status == CheckStatus.WARNING
			assert partial_result.message == (
				f"Package {partial_result.details['package']} is out of date. "
				f"Installed version: {partial_result.details['version']} - "
				f"available version: {repo_versions[partial_result.details['package']]}"
			)

		captured_output = captured_function_output(print_check_result, check_result=result, console=console)

		for name, version in installed_versions.items():
			assert f"Package {name} is out of date. Installed version: {version}" in captured_output


def test_check_system_packages_open_suse() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False, width=1000, highlight=False)
	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	zypper_lines = [
		"S  | Name                 | Typ   | Version             | Arch   | Repository",
		"---+----------------------+-------+---------------------+--------+------------------------------",
	] + [
		f"i  | {name}            | Paket | {version} | x86_64 | opsi 4.2 (openSUSE_Leap_15.2)"
		for name, version in installed_versions.items()
	]

	class Proc:  # pylint: disable=too-few-public-methods
		stdout = "\n".join(zypper_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"opensuse"})),
	):
		result = check_system_packages()
		captured_output = captured_function_output(print_check_result, check_result=result, console=console)

		for name, version in repo_versions.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK
		for partial_result in result.partial_results:
			assert partial_result.check_status == CheckStatus.OK
			assert partial_result.message == (
				f"Package {partial_result.details['package']} is up to date. "
				f"Installed version: {partial_result.details['version']}"
			)


def test_check_system_packages_redhat() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False, width=1000, highlight=False)
	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	yum_lines = ["Subscription Management Repositorys werden aktualisiert.", "Installierte Pakete"] + [
		f"{name}.x86_64     {version}    @home_uibmz_opsi_4.2_stable "
		for name, version in installed_versions.items()
	]

	class Proc:  # pylint: disable=too-few-public-methods
		stdout = "\n".join(yum_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"rhel"})),
	):
		result = check_system_packages()
		captured_output = captured_function_output(print_check_result, check_result=result, console=console)

		for name, version in repo_versions.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK

		for partial_result in result.partial_results:
			assert partial_result.check_status == CheckStatus.OK
			assert partial_result.message == (
				f"Package {partial_result.details['package']} is up to date. "
				f"Installed version: {partial_result.details['version']}"
			)


def test_health_check() -> None:
	sync_clean_redis()
	results = health_check()
	assert len(results) == 8
	for result in results:
		#print(result.check_id, result.check_status)
		if result.check_id not in ("system_packages", "opsi_packages", "depotservers"):
			assert result.check_status == CheckStatus.OK


def test_check_deprecated_calls(
	test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	sync_clean_redis()
	console = Console(log_time=False, width=1000)
	result = check_deprecated_calls()
	captured_output = captured_function_output(print_check_result, check_result=result, console=console)
	assert "No deprecated method calls found." in captured_output
	assert result.check_status == CheckStatus.OK

	rpc = {"id": 1, "method": DEPRECATED_METHOD, "params": []}
	current_dt = datetime.utcnow().astimezone(timezone.utc)
	with catch_warnings():
		simplefilter("ignore")
		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	assert res.status_code == 200
	time.sleep(3)

	result = check_deprecated_calls()
	captured_output = captured_function_output(print_check_result, check_result=result, console=console)

	#print(result)
	assert result.check_status == CheckStatus.WARNING
	assert len(result.partial_results) == 1
	partial_result = result.partial_results[0]
	#print(partial_result)
	assert partial_result.details["method"] == DEPRECATED_METHOD
	assert partial_result.details["calls"] == "1"
	assert partial_result.details["last_call"]
	last_call_dt = datetime.fromisoformat(partial_result.details["last_call"])
	assert (last_call_dt - current_dt).total_seconds() < 3
	assert isinstance(partial_result.details["applications"], list)
	assert partial_result.details["applications"] == ["testclient"]


def test_check_licenses(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	result = check_opsi_licenses()
	assert result.check_status == "ok"
	assert result.partial_results is not None
