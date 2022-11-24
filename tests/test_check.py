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
from colorama import Fore, Style  # type: ignore[import]
from MySQLdb import OperationalError  # type: ignore[import]
from redis.exceptions import ConnectionError as RedisConnectionError

from opsiconfd.check import (
	PACKAGES,
	check_deprecated_calls,
	check_mysql,
	check_redis,
	check_system_packages,
	get_repo_versions,
	health_check,
)

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	config,
	sync_clean_redis,
	test_client,
)

DEPRECATED_METHOD = "getClientIds_list"


def captured_function_output(func: Callable, args: Dict[str, Any]) -> Dict[str, Any]:
	captured_output = io.StringIO()
	sys.stdout = captured_output
	result = func(*args)
	sys.stdout = sys.__stdout__

	return {"captured_output": captured_output.getvalue(), "data": result}


def test_check_redis(config) -> None:
	config.log_level_stderr = 5
	result = captured_function_output(check_redis, {"print_messages": True})

	assert (
		result.get("captured_output")
		== Fore.WHITE
		+ Style.BRIGHT
		+ "\t- Checking redis:                                "
		+ Style.RESET_ALL
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "OK"
		+ Style.RESET_ALL
		+ "\n"
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "		Redis is running and Redis-Timeseries is loaded."
		+ Style.RESET_ALL
		+ "\n"
	)

	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"

	result = captured_function_output(check_redis, {})

	assert result.get("captured_output") == ""
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"


def test_check_redis_error() -> None:

	with mock.patch("opsiconfd.utils.get_redis_connection", side_effect=RedisConnectionError("Redis test error")):
		result = captured_function_output(check_redis, {"print_messages": True})
		assert (
			result.get("captured_output")
			== Fore.WHITE
			+ Style.BRIGHT
			+ "\t- Checking redis:                                "
			+ Style.RESET_ALL
			+ Fore.RED
			+ Style.BRIGHT
			+ "ERROR"
			+ Style.RESET_ALL
			+ "\n"
			+ Fore.RED
			+ Style.BRIGHT
			+ "\t\tCannot connect to redis!"
			+ Style.RESET_ALL
			+ "\n"
		)
		data = result.get("data", {})
		assert data.get("status") is not None
		assert data["status"] == "error"
		assert data["message"] == "Redis test error"


def test_check_mysql(config) -> None:
	config.log_level_stderr = 5
	result = captured_function_output(check_mysql, {"print_messages": True})

	assert (
		result.get("captured_output")
		== Fore.WHITE
		+ Style.BRIGHT
		+ "\t- Checking mysql:                                "
		+ Style.RESET_ALL
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "OK"
		+ Style.RESET_ALL
		+ "\n"
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "\t\tConnection to mysql is working."
		+ Style.RESET_ALL
		+ "\n"
	)
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"
	assert data["message"] == "Connection to mysql is working."


def test_check_mysql_error(config) -> None:
	config.log_level_stderr = 5
	with mock.patch(
		"opsiconfd.check.get_mysql", side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")')
	):
		result = captured_function_output(check_mysql, {"print_messages": True})

		assert (
			result.get("captured_output")
			== Fore.WHITE
			+ Style.BRIGHT
			+ "\t- Checking mysql:                                "
			+ Style.RESET_ALL
			+ Fore.RED
			+ Style.BRIGHT
			+ "ERROR"
			+ Style.RESET_ALL
			+ "\n"
			+ Fore.RED
			+ Style.BRIGHT
			+ '\t\tCould not connect to mysql: (MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'
			+ Style.RESET_ALL
			+ "\n"
		)
		data = result.get("data", {})
		assert data.get("status") is not None
		assert data["status"] == "error"
		assert data["message"] == '(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'

		config.log_level_stderr = 4
		result = captured_function_output(check_mysql, {"print_messages": True})

		assert (
			result.get("captured_output")
			== Fore.WHITE
			+ Style.BRIGHT
			+ "\t- Checking mysql:                                "
			+ Style.RESET_ALL
			+ Fore.RED
			+ Style.BRIGHT
			+ "ERROR"
			+ Style.RESET_ALL
			+ "\n"
		)


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


def test_check_system_packages_debian(config) -> None:
	config.log_level_stderr = 5
	# test up to date packages - status sould be ok and output should be green
	packages = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	dpkg_lines = []
	test_package_versions = {}

	for name, version in packages.items():
		dpkg_lines.append(f"ii  {name}                         {version}                       amd64        Package description")
		test_package_versions[name] = {"version": version, "status": None}

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.execute", mock.PropertyMock(return_value=dpkg_lines)),
		mock.patch("opsiconfd.check.isOpenSUSE", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isSLES", mock.PropertyMock(return_value=False)),
	):
		result = captured_function_output(check_system_packages, {"print_messages": True})

		text = Fore.WHITE + Style.BRIGHT + "\t- Checking system packages:                      " + Style.RESET_ALL
		text = text + Fore.GREEN + Style.BRIGHT + "OK" + Style.RESET_ALL + "\n"
		for name, version in packages.items():
			text = (
				text
				+ Fore.GREEN
				+ Style.BRIGHT
				+ f"\t\tPackage {name} is up to date. Installed version: {version}"
				+ Style.RESET_ALL
				+ "\n"
			)
		assert result.get("captured_output") == text
		data = result.get("data", {})
		partial_check = data.get("partial_checks", {})
		for name, version in packages.items():
			assert data.get("message") == "All packages up to date."
			assert data.get("status") == "ok"
			assert partial_check.get(name, {}).get("status") is not None
			assert partial_check.get(name, {}).get("status") == "ok"
			assert partial_check[name]["message"] == f"Installed version: {version}"

	# test outdated packages - status sould be warn and output sould be in yellow
	packages = {"opsiconfd": "4.2.0.100-1", "opsi-utils": "4.2.0.100-1"}
	dpkg_lines = []
	for name, version in packages.items():  # pylint: disable=use-list-copy
		dpkg_lines.append(f"ii  {name}                         {version}                       amd64        Package description")

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.execute", mock.PropertyMock(return_value=dpkg_lines)),
		mock.patch("opsiconfd.check.isOpenSUSE", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isSLES", mock.PropertyMock(return_value=False)),
	):
		result = captured_function_output(check_system_packages, {"print_messages": True})
		text = Fore.WHITE + Style.BRIGHT + "\t- Checking system packages:                      " + Style.RESET_ALL
		text = text + Fore.YELLOW + Style.BRIGHT + "WARNING" + Style.RESET_ALL + "\n"
		for name, version in packages.items():
			text = (
				text
				+ Fore.YELLOW
				+ Style.BRIGHT
				+ f"\t\tPackage {name} is outdated. Installed version: {version} - available version: {test_package_versions[name]['version']}"
				+ Style.RESET_ALL
				+ "\n"
			)
		assert result.get("captured_output") == text
		data = result.get("data", {})
		partial_check = data.get("partial_checks", {})
		for name, version in packages.items():
			assert data.get("message") == "Out of 2 packages checked, 0 are not installed and 2 are out of date."
			assert data.get("status") == "warn"
			assert partial_check.get(name, {}).get("status") is not None
			assert partial_check.get(name, {}).get("status") == "warn"
			assert (
				partial_check[name]["message"]
				== f"Package {name} is outdated. Installed version: {version} - available version: {test_package_versions[name]['version']}"
			)


def test_check_system_packages_open_suse() -> None:
	packages = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}

	zypper_lines = [
		"S  | Name                 | Typ   | Version             | Arch   | Repository",
		"---+----------------------+-------+---------------------+--------+------------------------------",
	]
	test_package_versions = {}

	for name, version in packages.items():
		zypper_lines.append(f"i  | {name}            | Paket | {version} | x86_64 | opsi 4.2 (openSUSE_Leap_15.2)")
		test_package_versions[name] = {"version": version, "status": None}

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.execute", mock.PropertyMock(return_value=zypper_lines)),
		mock.patch("opsiconfd.check.isOpenSUSE", mock.PropertyMock(return_value=True)),
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isSLES", mock.PropertyMock(return_value=False)),
	):
		result = captured_function_output(check_system_packages, {"print_messages": True})

		text = Fore.WHITE + Style.BRIGHT + "Checking system packages..." + Style.RESET_ALL + "\n"
		for name, version in packages.items():
			text = text + Fore.GREEN + Style.BRIGHT + f"Package {name} is up to date. Installed version: {version}" + Style.RESET_ALL + "\n"
		assert result.get("captured_output") == text
		data = result.get("data", {})
		partial_check = data.get("partial_checks", {})
		for name, version in packages.items():
			assert data.get("details") == "All packages up to date."
			assert data.get("status") == "ok"
			assert partial_check.get(name, {}).get("status") is not None
			assert partial_check.get(name, {}).get("status") == "ok"
			assert partial_check[name]["details"] == f"Installed version: {version}"


def test_check_system_packages_redhat() -> None:
	packages = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}

	yum_lines = ["Subscription Management Repositorys werden aktualisiert.", "Installierte Pakete"]
	test_package_versions = {}

	for name, version in packages.items():
		yum_lines.append(f"{name}.x86_64     {version}    @home_uibmz_opsi_4.2_stable ")
		test_package_versions[name] = {"version": version, "status": None}

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.execute", mock.PropertyMock(return_value=yum_lines)),
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=True)),
	):
		result = captured_function_output(check_system_packages, {"print_messages": True})

		text = Fore.WHITE + Style.BRIGHT + "Checking system packages..." + Style.RESET_ALL + "\n"
		for name, version in packages.items():
			text = text + Fore.GREEN + Style.BRIGHT + f"Package {name} is up to date. Installed version: {version}" + Style.RESET_ALL + "\n"
		assert result.get("captured_output") == text
		data = result.get("data", {})
		partial_check = data.get("partial_checks", {})
		for name, version in packages.items():
			assert data.get("details") == "All packages up to date."
			assert data.get("status") == "ok"
			assert partial_check.get(name, {}).get("status") is not None
			assert partial_check.get(name, {}).get("status") == "ok"
			assert partial_check[name]["details"] == f"Installed version: {version}"


def test_health_check() -> None:
	result = health_check()
	assert result.get("system_packages") is not None
	assert result.get("redis") is not None
	assert result["redis"]["status"] == "ok"
	assert result.get("mysql") is not None
	assert result["mysql"]["status"] == "ok"


def test_check_deprecated_calls(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument

	sync_clean_redis()

	result = captured_function_output(check_deprecated_calls, {"print_messages": True})

	assert (
		result.get("captured_output")
		== Fore.WHITE
		+ Style.BRIGHT
		+ "Checking calls of deprecated methods..."
		+ Style.RESET_ALL
		+ "\n"
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "No deprecated method calls found."
		+ Style.RESET_ALL
		+ "\n"
	)
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"

	rpc = {"id": 1, "method": DEPRECATED_METHOD, "params": []}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	assert res.status_code == 200

	result = captured_function_output(check_deprecated_calls, {"print_messages": True})
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "warn"
	assert data["details"] is not None
	assert data["details"][DEPRECATED_METHOD] is not None
	assert data["details"][DEPRECATED_METHOD]["calls"] == "1"
	assert isinstance(data["details"][DEPRECATED_METHOD]["clients"], set)
	assert data["details"][DEPRECATED_METHOD]["clients"] == {"testclient"}
