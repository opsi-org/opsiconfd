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
from redis.exceptions import ConnectionError as RedisConnectionError

from opsiconfd.check import (
	PACKAGES,
	check_mysql,
	check_redis,
	check_system_packages,
	get_repo_versions,
)


def captured_function_output(func: Callable, args: Dict[str, Any]) -> Dict[str, Any]:
	captured_output = io.StringIO()
	sys.stdout = captured_output
	result = func(**args)
	sys.stdout = sys.__stdout__

	return {"captured_output": captured_output.getvalue(), "data": result}


def test_check_redis() -> None:

	result = captured_function_output(check_redis, {"print_messages": True})

	assert (
		result.get("captured_output")
		== Fore.WHITE
		+ Style.BRIGHT
		+ "Checking redis..."
		+ Style.RESET_ALL
		+ "\n"
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "Redis is running and Redis-Timeseries is loaded."
		+ Style.RESET_ALL
		+ "\n"
	)
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"

	result = captured_function_output(check_redis, {"print_messages": False})

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
			+ "Checking redis..."
			+ Style.RESET_ALL
			+ "\n"
			+ Fore.RED
			+ Style.BRIGHT
			+ "Cannot connect to redis!"
			+ Style.RESET_ALL
			+ "\n"
		)
		data = result.get("data", {})
		assert data.get("status") is not None
		assert data["status"] == "error"
		assert data["details"] == "Redis test error"


def test_check_mysql() -> None:

	result = captured_function_output(check_mysql, {"print_messages": True})

	assert (
		result.get("captured_output")
		== Fore.WHITE
		+ Style.BRIGHT
		+ "Checking mysql..."
		+ Style.RESET_ALL
		+ "\n"
		+ Fore.GREEN
		+ Style.BRIGHT
		+ "Connection to mysql is working."
		+ Style.RESET_ALL
		+ "\n"
	)
	data = result.get("data", {})
	assert data.get("status") is not None
	assert data["status"] == "ok"
	assert data["details"] == "Connection to mysql is working."


def test_check_mysql_error() -> None:

	with mock.patch("opsiconfd.check.execute", side_effect=RuntimeError("Command '[...]' failed (1):\nMysql test error")):
		result = captured_function_output(check_mysql, {"print_messages": True})

		assert (
			result.get("captured_output")
			== Fore.WHITE
			+ Style.BRIGHT
			+ "Checking mysql..."
			+ Style.RESET_ALL
			+ "\n"
			+ Fore.RED
			+ Style.BRIGHT
			+ "Could not connect to mysql: Mysql test error"
			+ Style.RESET_ALL
			+ "\n"
		)
		data = result.get("data", {})
		assert data.get("status") is not None
		assert data["status"] == "error"
		assert data["details"] == "Mysql test error"


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


def test_check_system_packages_debian() -> None:
	packages = {
		"opsiconfd": "4.2.0.200-1",
		"opsi-utils": "4.2.0.180-1"
	}
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
		mock.patch("opsiconfd.check.isSLES", mock.PropertyMock(return_value=False))
	):
		result = captured_function_output(check_system_packages, {"print_messages": True})

		text = Fore.WHITE + Style.BRIGHT + "Checking system packages..." + Style.RESET_ALL + "\n"
		for name, version in packages.items():
			text = text + Fore.GREEN + Style.BRIGHT + f"Package {name} is up to date. Installed version: {version}" + Style.RESET_ALL + "\n"
		assert result.get("captured_output") == text
		data = result.get("data", {})
		for name, version in packages.items():
			assert data.get(name, {}).get("status") is not None
			assert data[name]["status"] == "ok"
			assert data[name]["details"] == f"Installed version: {version}"


def test_check_system_packages_open_suse() -> None:
	packages = {
		"opsiconfd": "4.2.0.200-1",
		"opsi-utils": "4.2.0.180-1"
	}

	zypper_lines = [
		"S  | Name                 | Typ   | Version             | Arch   | Repository",
		"---+----------------------+-------+---------------------+--------+------------------------------"
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
		mock.patch("opsiconfd.check.isSLES", mock.PropertyMock(return_value=False))
	):
		result2 = captured_function_output(check_system_packages, {"print_messages": True})

		text = Fore.WHITE + Style.BRIGHT + "Checking system packages..." + Style.RESET_ALL + "\n"
		for name, version in packages.items():
			text = text + Fore.GREEN + Style.BRIGHT + f"Package {name} is up to date. Installed version: {version}" + Style.RESET_ALL + "\n"
		assert result2.get("captured_output") == text
		data2 = result2.get("data", {})
		for name, version in packages.items():
			assert data2.get(name, {}).get("status") is not None
			assert data2[name]["status"] == "ok"
			assert data2[name]["details"] == f"Installed version: {version}"


def test_check_system_packages_redhat() -> None:
	packages = {
		"opsiconfd": "4.2.0.200-1",
		"opsi-utils": "4.2.0.180-1"
	}

	yum_lines = [
		"Subscription Management Repositorys werden aktualisiert.",
		"Installierte Pakete"
	]
	test_package_versions = {}

	for name, version in packages.items():
		yum_lines.append(f"{name}.x86_64     {version}    @home_uibmz_opsi_4.2_stable ")
		test_package_versions[name] = {"version": version, "status": None}

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=test_package_versions)),
		mock.patch("opsiconfd.check.execute", mock.PropertyMock(return_value=yum_lines)),
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=True))
	):
		result2 = captured_function_output(check_system_packages, {"print_messages": True})

		text = Fore.WHITE + Style.BRIGHT + "Checking system packages..." + Style.RESET_ALL + "\n"
		for name, version in packages.items():
			text = text + Fore.GREEN + Style.BRIGHT + f"Package {name} is up to date. Installed version: {version}" + Style.RESET_ALL + "\n"
		assert result2.get("captured_output") == text
		data2 = result2.get("data", {})
		for name, version in packages.items():
			assert data2.get(name, {}).get("status") is not None
			assert data2[name]["status"] == "ok"
			assert data2[name]["details"] == f"Installed version: {version}"
