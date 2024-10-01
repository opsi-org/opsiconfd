# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

from unittest import mock

import requests
from rich.console import Console

import opsiconfd.check.system  # noqa: F401
from opsiconfd.check.cache import check_cache_clear
from opsiconfd.check.cli import process_check_result
from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.check.opsipackages import get_available_product_versions
from opsiconfd.check.system import CHECK_SYSTEM_PACKAGES, get_repo_versions
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import (  # noqa: F401
	ACL_CONF_41,
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	captured_function_output,
	clean_mysql,
	get_config,
	get_opsi_config,
	sync_clean_redis,
	test_client,
)
from tests.utils import (
	config as test_config,  # noqa: F401
)

DEPRECATED_METHOD = "getClientIds_list"


def test_check_disk_usage() -> None:
	result = check_manager.get("disk_usage").run(use_cache=False)
	assert result.check_status


def test_get_repo_versions() -> None:
	result = get_repo_versions()
	for package in CHECK_SYSTEM_PACKAGES:
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


def test_check_system_packages_debian() -> None:
	# test up to date packages - status sould be ok and output should be green
	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	console = Console(log_time=False, force_terminal=False, width=1000)
	dpkg_lines = [
		f"ii  {name}                         {version}                       amd64        Package description"
		for name, version in installed_versions.items()
	]

	class Proc:
		stdout = "\n".join(dpkg_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"debian"})),
	):
		result = check_manager.get("system_packages").run(use_cache=False)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in installed_versions.items():
			assert f"Package {name!r} is up to date. Installed version: {version!r}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK

		for partial_result in result.partial_results:
			assert partial_result.check_status == "ok"
			assert partial_result.message == (
				f"Package {partial_result.details['package']!r} is up to date. Installed version: {partial_result.details['version']!r}"
			)

	# test outdated packages - status sould be warn and output sould be in yellow
	installed_versions = {"opsiconfd": "4.2.0.100-1", "opsi-utils": "4.2.0.100-1"}
	dpkg_lines = [
		f"ii  {name}                         {version}                       amd64        Package description"
		for name, version in installed_versions.items()
	]
	Proc.stdout = "\n".join(dpkg_lines) + "\n"

	check_cache_clear("all")
	with (
		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"debian"})),
	):
		result = check_manager.get("system_packages").run(use_cache=False)

		assert result.message == "Out of 2 packages checked, 0 are not installed and 2 are out of date."
		assert result.check_status == CheckStatus.WARNING
		for partial_result in result.partial_results:
			assert partial_result.check_status == CheckStatus.WARNING
			assert partial_result.message == (
				f"Package {partial_result.details['package']!r} is out of date. "
				f"Installed version {partial_result.details['version']!r} < "
				f"available version {repo_versions[partial_result.details['package']]!r}"
			)

		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in installed_versions.items():
			assert f"Package {name!r} is out of date. Installed version {version!r}" in captured_output


def test_check_system_packages_open_suse() -> None:
	console = Console(log_time=False, force_terminal=False, width=1000)
	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	zypper_lines = [
		"S  | Name                 | Typ   | Version             | Arch   | Repository",
		"---+----------------------+-------+---------------------+--------+------------------------------",
	] + [
		f"i  | {name}            | Paket | {version} | x86_64 | opsi 4.2 (openSUSE_Leap_15.2)"
		for name, version in installed_versions.items()
	]

	class Proc:
		stdout = "\n".join(zypper_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"opensuse"})),
	):
		result = check_manager.get("system_packages").run(use_cache=False)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in repo_versions.items():
			assert f"Package {name!r} is up to date. Installed version: {version!r}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK
		for partial_result in result.partial_results:
			assert partial_result.check_status == CheckStatus.OK
			assert partial_result.message == (
				f"Package {partial_result.details['package']!r} is up to date. Installed version: {partial_result.details['version']!r}"
			)


def test_check_system_packages_redhat() -> None:
	console = Console(log_time=False, force_terminal=False, width=1000)
	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	yum_lines = ["Subscription Management Repositorys werden aktualisiert.", "Installierte Pakete"] + [
		f"{name}.x86_64     {version}    @home_uibmz_opsi_4.2_stable " for name, version in installed_versions.items()
	]

	class Proc:
		stdout = "\n".join(yum_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"rhel"})),
	):
		result = check_manager.get("system_packages").run(use_cache=False)
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in repo_versions.items():
			assert f"Package {name!r} is up to date. Installed version: {version!r}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK

		for partial_result in result.partial_results:
			assert partial_result.check_status == CheckStatus.OK
			assert partial_result.message == (
				f"Package {partial_result.details['package']!r} is up to date. Installed version: {partial_result.details['version']!r}"
			)


def test_get_available_product_versions() -> None:
	product_ids = ["opsi-script", "opsi-client-agent", "opsi-linux-client-agent", "opsi-mac-client-agent", "hwaudit", "win10", "hwinvent"]
	available_packages = get_available_product_versions(product_ids)
	assert list(available_packages) == product_ids
	for version in available_packages.values():
		assert version != "0.0"
