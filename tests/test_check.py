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
from typing import Any, Callable, Dict
from unittest import mock

import requests
from MySQLdb import OperationalError  # type: ignore[import]
from redis.exceptions import ConnectionError as RedisConnectionError
from rich.console import Console

from opsiconfd.check import (
	PACKAGES,
	CheckStatus,
	check_deprecated_calls,
	check_mysql,
	check_opsi_licenses,
	check_redis,
	check_system_packages,
	get_repo_versions,
	health_check,
	print_check_deprecated_calls_result,
	print_check_result,
	print_check_system_packages_result,
)

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	sync_clean_redis,
	test_client,
)

DEPRECATED_METHOD = "getClientIds_list"


def captured_function_output(func: Callable, args: Dict[str, Any]) -> str:
	captured_output = io.StringIO()
	sys.stdout = captured_output
	result = func(**args)
	sys.stdout = sys.__stdout__
	print(result)

	return captured_output.getvalue()


def test_check_redis() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False)
	result = check_redis()
	print(result)
	captured_output = captured_function_output(print_check_result, {"check_result": result, "console": console})
	print(captured_output)
	assert "Redis is running and RedisTimeSeries is loaded." in captured_output

	assert result.get("status") is not None
	assert result["status"] == "ok"


def test_check_redis_error() -> None:

	with mock.patch("opsiconfd.utils.get_redis_connection", side_effect=RedisConnectionError("Redis test error")):
		console = Console(log_time=False)
		result = check_redis()
		captured_output = captured_function_output(print_check_result, {"check_result": result, "console": console})

		assert "Cannot connect to Redis" in captured_output
		assert result.get("status") is not None
		assert result["status"] == "error"
		assert result["message"] == "Cannot connect to Redis: Redis test error"


def test_check_mysql() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False)
	result = check_mysql()
	captured_output = captured_function_output(print_check_result, {"check_result": result, "console": console})

	assert "Connection to MySQL is working." in captured_output
	assert result.get("status") is not None
	assert result["status"] == "ok"
	assert result["message"] == "Connection to MySQL is working."


def test_check_mysql_error() -> None:  # pylint: disable=redefined-outer-name

	with mock.patch(
		"opsiconfd.check.get_mysql", side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")')
	):
		console = Console(log_time=False)
		result = check_mysql()
		captured_output = captured_function_output(print_check_result, {"check_result": result, "console": console})

		assert "Could not connect to MySQL:" in captured_output
		assert "(MySQLdb.OperationalError)" in captured_output
		assert result.get("status") is not None
		assert result["status"] == "error"
		assert result["message"] == 'Could not connect to MySQL: (MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'


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
			assert result.get(package, {}).get("version") == "4.2.0.286-1"
		if package == "opsi-utils":
			assert result.get(package, {}).get("version") == "4.2.0.183-1"


def test_check_system_packages_debian() -> None:  # pylint: disable=redefined-outer-name
	# test up to date packages - status sould be ok and output should be green
	packages = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	dpkg_lines = []
	test_package_versions = {}
	console = Console(log_time=False, width=1000)
	for name, version in packages.items():
		dpkg_lines.append(f"ii  {name}                         {version}                       amd64        Package description")
		test_package_versions[name] = {"version": version, "status": None}

	class Proc:  # pylint: disable=too-few-public-methods
		stdout = "\n".join(dpkg_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"debian"})),
	):

		result = check_system_packages()
		captured_output = captured_function_output(print_check_system_packages_result, {"check_result": result, "console": console})

		for name, version in packages.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output
		partial_check = result.get("partial_checks", {})
		for name, version in packages.items():
			assert result.get("message") == "All packages are up to date."
			assert result.get("status") == CheckStatus.OK
			assert partial_check.get(name, {}).get("status") is not None
			assert partial_check.get(name, {}).get("status") == "ok"
			assert partial_check[name]["message"] == f"Package {name} is up to date. Installed version: {version}"

	# test outdated packages - status sould be warn and output sould be in yellow
	packages = {"opsiconfd": "4.2.0.100-1", "opsi-utils": "4.2.0.100-1"}
	dpkg_lines = []
	for name, version in packages.items():  # pylint: disable=use-list-copy
		dpkg_lines.append(f"ii  {name}                         {version}                       amd64        Package description")

	Proc.stdout = "\n".join(dpkg_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"debian"})),
	):
		result = check_system_packages()
		captured_output = captured_function_output(print_check_system_packages_result, {"check_result": result, "console": console})

		for name, version in packages.items():
			assert f"Package {name} is out of date. Installed version: {version}" in captured_output

		partial_check = result.get("partial_checks", {})
		for name, version in packages.items():
			assert result.get("message") == "Out of 2 packages checked, 0 are not installed and 2 are out of date."
			assert result.get("status") == CheckStatus.WARNING
			assert partial_check.get(name, {}).get("status") is not None
			assert partial_check.get(name, {}).get("status") == CheckStatus.WARNING
			assert (
				partial_check[name]["message"]
				== f"Package {name} is out of date. Installed version: {version} - available version: {test_package_versions[name]['version']}"
			)


def test_check_system_packages_open_suse() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False, width=1000)
	packages = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}

	zypper_lines = [
		"S  | Name                 | Typ   | Version             | Arch   | Repository",
		"---+----------------------+-------+---------------------+--------+------------------------------",
	]
	test_package_versions = {}

	for name, version in packages.items():
		zypper_lines.append(f"i  | {name}            | Paket | {version} | x86_64 | opsi 4.2 (openSUSE_Leap_15.2)")
		test_package_versions[name] = {"version": version, "status": None}

	class Proc:  # pylint: disable=too-few-public-methods
		stdout = "\n".join(zypper_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"opensuse"})),
	):
		result = check_system_packages()
		captured_output = captured_function_output(print_check_system_packages_result, {"check_result": result, "console": console})

		for name, version in packages.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output
		partial_check = result.get("partial_checks", {})
		for name, version in packages.items():
			assert result.get("message") == "All packages are up to date."
			assert result.get("status") == CheckStatus.OK
			assert partial_check.get(name, {}).get("status") is not None
			assert partial_check.get(name, {}).get("status") == CheckStatus.OK
			assert partial_check[name]["message"] == f"Package {name} is up to date. Installed version: {version}"


def test_check_system_packages_redhat() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False, width=1000)
	packages = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}

	yum_lines = ["Subscription Management Repositorys werden aktualisiert.", "Installierte Pakete"]
	test_package_versions = {}

	for name, version in packages.items():
		yum_lines.append(f"{name}.x86_64     {version}    @home_uibmz_opsi_4.2_stable ")
		test_package_versions[name] = {"version": version, "status": None}

	class Proc:  # pylint: disable=too-few-public-methods
		stdout = "\n".join(yum_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"rhel"})),
	):
		result = check_system_packages()
		captured_output = captured_function_output(print_check_system_packages_result, {"check_result": result, "console": console})

		for name, version in packages.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output
		partial_check = result.get("partial_checks", {})
		for name, version in packages.items():
			assert result.get("message") == "All packages are up to date."
			assert result.get("status") == CheckStatus.OK
			assert partial_check.get(name, {}).get("status") is not None
			assert partial_check.get(name, {}).get("status") == CheckStatus.OK
			assert partial_check[name]["message"] == f"Package {name} is up to date. Installed version: {version}"


def test_health_check() -> None:
	result = health_check()
	assert result.get("system_packages") is not None
	assert result.get("redis") is not None
	assert result["redis"]["status"] == CheckStatus.OK
	assert result.get("mysql") is not None
	assert result["mysql"]["status"] == CheckStatus.OK
	assert result.get("opsi_packages") is not None
	assert result.get("licenses") is not None
	assert result["licenses"]["status"] == CheckStatus.OK
	assert result.get("deprecated_calls") is not None
	assert result["deprecated_calls"]["status"] == CheckStatus.OK


def test_check_deprecated_calls(
	test_client: OpsiconfdTestClient  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	sync_clean_redis()
	console = Console(log_time=False, width=1000)
	result = check_deprecated_calls()
	captured_output = captured_function_output(print_check_deprecated_calls_result, {"check_result": result, "console": console})
	assert "No deprecated method calls found." in captured_output
	assert result.get("status") is not None
	assert result["status"] == CheckStatus.OK

	rpc = {"id": 1, "method": DEPRECATED_METHOD, "params": []}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_deprecated_calls()
	captured_output = captured_function_output(print_check_deprecated_calls_result, {"check_result": result, "console": console})

	assert result.get("status") is not None
	assert result["status"] == CheckStatus.WARNING
	assert result["details"] is not None
	assert result["details"][DEPRECATED_METHOD] is not None
	assert result["details"][DEPRECATED_METHOD]["calls"] == "1"
	assert isinstance(result["details"][DEPRECATED_METHOD]["clients"], set)
	assert result["details"][DEPRECATED_METHOD]["clients"] == {"testclient"}


def test_check_licenses(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument

	result = check_opsi_licenses()
	assert result.get("status") is not None
	assert result["status"] == "ok"
	assert result["partial_checks"] is not None
