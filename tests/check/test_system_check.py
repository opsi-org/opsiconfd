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
from mock import Mock  # type: ignore[import]
from rich.console import Console

from opsiconfd.check.cache import check_cache_clear
from opsiconfd.check.cli import process_check_result
from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.check.opsipackages import get_available_product_versions
from opsiconfd.check.register import register_checks
from opsiconfd.check.system import (
	CHECK_SYSTEM_PACKAGES,
	disk_usage_check,
	get_repo_versions,
	system_eol_check,
	system_packages_check,
	system_repositories_check,
)
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import (  # noqa: F401
	ACL_CONF_41,
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	captured_function_output,
	clean_mysql,
	cleanup_checks,
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
	check_manager.register(system_eol_check, disk_usage_check, system_repositories_check, system_packages_check)
	result = check_manager.get("disk_usage").run(clear_cache=True)
	assert result.check_status


def test_get_repo_versions() -> None:
	check_manager.register(system_eol_check, disk_usage_check, system_repositories_check, system_packages_check)
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
	check_manager.register(system_eol_check, disk_usage_check, system_repositories_check, system_packages_check)
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
		result = check_manager.get("system_packages").run(clear_cache=True)
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
		result = check_manager.get("system_packages").run(clear_cache=True)

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
	check_manager.register(system_eol_check, disk_usage_check, system_repositories_check, system_packages_check)
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
		result = check_manager.get("system_packages").run(clear_cache=True)
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
	check_manager.register(system_eol_check, disk_usage_check, system_repositories_check, system_packages_check)
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
		result = check_manager.get("system_packages").run(clear_cache=True)
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
	register_checks()
	product_ids = ["opsi-script", "opsi-client-agent", "opsi-linux-client-agent", "opsi-mac-client-agent", "hwaudit", "win10", "hwinvent"]
	available_packages = get_available_product_versions(product_ids)
	assert list(available_packages) == product_ids
	for version in available_packages.values():
		assert version != "0.0"


def test_check_system_repos() -> None:
	check_manager.register(system_eol_check, disk_usage_check, system_repositories_check, system_packages_check)
	# Test debian 10 with debian 11 repository and debian 10 repository
	with mock.patch("opsiconfd.check.system.linux_distro_id") as mock_distro_id:
		mock_distro_id.return_value = "debian"
		with mock.patch("opsiconfd.check.system.linux_distro_version_id") as mock_distro_version:
			mock_distro_version.return_value = "10"
			with mock.patch("opsiconfd.check.system.run") as mock_run:
				mock_run.return_value = Mock(
					stdout=(
						"Package files:\n"
						"100 /var/lib/dpkg/status\n"
						"	release a=now\n"
						"500 https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.3:/stable/Debian_11  Packages\n"
						"	release o=obs://build.opensuse.org/home:uibmz:opsi:4.3:stable/Debian_11,n=Debian_11,l=home:uibmz:opsi:4.3:stable,c=\n"
						"	origin download.opensuse.org\n"
						"500 https://apt.grafana.com stable/main amd64 Packages\n"
						"	release o=. stable,a=stable,n=stable,l=. stable,c=main,b=amd64\n"
						"	origin apt.grafana.com\n"
						"Pinned packages:\n"
					)
				)
				result = check_manager.get("system_repositories").run(clear_cache=True)
				assert result.check_status == CheckStatus.ERROR
				assert (
					result.message
					== "System and opsi repositories are incompatible. System 'debian 10' using repository: https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.3:/stable/Debian_11"
				)

		with mock.patch("opsiconfd.check.system.run") as mock_run:
			mock_run.return_value = Mock(
				stdout=(
					"Package files:\n"
					"100 /var/lib/dpkg/status\n"
					"	release a=now\n"
					"500 https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.3:/stable/Debian_10  Packages\n"
					"	release o=obs://build.opensuse.org/home:uibmz:opsi:4.3:stable/Debian_11,n=Debian_10,l=home:uibmz:opsi:4.3:stable,c=\n"
					"	origin download.opensuse.org\n"
					"500 https://apt.grafana.com stable/main amd64 Packages\n"
					"	release o=. stable,a=stable,n=stable,l=. stable,c=main,b=amd64\n"
					"	origin apt.grafana.com\n"
					"Pinned packages:\n"
				)
			)
			result = check_manager.get("system_repositories").run(clear_cache=True)
			assert result.check_status == CheckStatus.OK
			assert result.message == "No issues found with the system repositories."
	# test rocky 9 with rocky 8 repository and rocky 9 repository
	with mock.patch("opsiconfd.check.system.linux_distro_id") as mock_distro_id:
		mock_distro_id.return_value = "rocky"
		with mock.patch("opsiconfd.check.system.linux_distro_version_id") as mock_distro_version:
			mock_distro_version.return_value = "9"
			with mock.patch("opsiconfd.check.system.run") as mock_run:
				mock_run.return_value = Mock(
					stdout=(
						"Paketquellenkennung        Paketquellenname\n"
						"appstream                  Rocky Linux 9 - AppStream\n"
						"baseos                     Rocky Linux 9 - BaseOS\n"
						"epel                       Extra Packages for Enterprise Linux 9 - x86_64\n"
						"epel-cisco-openh264        Extra Packages for Enterprise Linux 9 openh264 (From Cisco) - x86_64\n"
						"extras                     Rocky Linux 9 - Extras\n"
						"grafana                    grafana\n"
						"home_uibmz_opsi_4.3_stable opsi 4.3 stable (RockyLinux_8)\n"
					)
				)
				result = check_manager.get("system_repositories").run(clear_cache=True)
				assert result.check_status == CheckStatus.ERROR
				assert (
					result.message
					== "System and opsi repositories are incompatible. System 'rocky 9' using repository: home_uibmz_opsi_4.3_stable opsi 4.3 stable (RockyLinux_8)"
				)
			with mock.patch("opsiconfd.check.system.run") as mock_run:
				mock_run.return_value = Mock(
					stdout=(
						"Paketquellenkennung        Paketquellenname\n"
						"appstream                  Rocky Linux 9 - AppStream\n"
						"baseos                     Rocky Linux 9 - BaseOS\n"
						"epel                       Extra Packages for Enterprise Linux 9 - x86_64\n"
						"epel-cisco-openh264        Extra Packages for Enterprise Linux 9 openh264 (From Cisco) - x86_64\n"
						"extras                     Rocky Linux 9 - Extras\n"
						"grafana                    grafana\n"
						"home_uibmz_opsi_4.3_stable opsi 4.3 stable (RockyLinux_9)\n"
					)
				)
				result = check_manager.get("system_repositories").run(clear_cache=True)
				assert result.check_status == CheckStatus.OK
				assert result.message == "No issues found with the system repositories."
	# Test openSUSE 15.5 with openSUSE 15.4 repository and openSUSE 15.5 repository
	with mock.patch("opsiconfd.check.system.linux_distro_id") as mock_distro_id:
		mock_distro_id.return_value = "opensuse-leap"
		with mock.patch("opsiconfd.check.system.linux_distro_version_id") as mock_distro_version:
			mock_distro_version.return_value = "15.5"
			with mock.patch("opsiconfd.check.system.run") as mock_run:
				mock_run.return_value = Mock(
					stdout=(
						"Die Repository-Prioritäten sind ohne Effekt. Alle aktivierten Repositorys teilen sich die gleiche Priorität.\n"
						" \n"
						"#  | Alias                               | Name                                                         | Enabled | GPG Check | Refresh\n"
						"---+-------------------------------------+--------------------------------------------------------------+---------+-----------+--------\n"
						"1 | grafana                             | grafana                                                      | Ja      | (r ) Ja   | Nein\n"
						"2 | home_uibmz_opsi_4.3_stable          | opsi 4.3 stable (openSUSE_Leap_15.4)                         | Ja      | ( p) Ja   | Nein\n"
						"3 | http-download.opensuse.org-0b97f368 | openSUSE 15.5-update-non-oss                                 | Ja      | (r ) Ja   | Ja\n"
						"4 | http-download.opensuse.org-1152c701 | openSUSE 15.5-update-oss                                     | Ja      | (r ) Ja   | Ja\n"
						"5 | non-oss-addon-15.5-0                | openSUSE 15.5-non-oss                                        | Ja      | (r ) Ja   | Ja\n"
						"6 | openSUSE-Leap-15.5-1_0              | openSUSE 15.5-oss                                            | Ja      | (r ) Ja   | Ja\n"
						"8 | repo-backports-update               | Update repository of openSUSE Backports                      | Ja      | (r ) Ja   | Ja\n"
						"10 | repo-sle-update                     | Update repository with updates from SUSE Linux Enterprise 15 | Ja      | (r ) Ja   | Ja\n"
					)
				)
				result = check_manager.get("system_repositories").run(clear_cache=True)
				assert result.check_status == CheckStatus.ERROR
				assert (
					result.message
					== "System and opsi repositories are incompatible. System 'opensuse-leap 15.5' using repository: opsi 4.3 stable (openSUSE_Leap_15.4)"
				)
			with mock.patch("opsiconfd.check.system.run") as mock_run:
				mock_run.return_value = Mock(
					stdout=(
						"Die Repository-Prioritäten sind ohne Effekt. Alle aktivierten Repositorys teilen sich die gleiche Priorität.\n"
						" \n"
						"#  | Alias                               | Name                                                         | Enabled | GPG Check | Refresh\n"
						"---+-------------------------------------+--------------------------------------------------------------+---------+-----------+--------\n"
						"1 | grafana                             | grafana                                                      | Ja      | (r ) Ja   | Nein\n"
						"2 | home_uibmz_opsi_4.3_stable          | opsi 4.3 stable (openSUSE_Leap_15.5)                         | Ja      | ( p) Ja   | Nein\n"
						"3 | http-download.opensuse.org-0b97f368 | openSUSE 15.5-update-non-oss                                 | Ja      | (r ) Ja   | Ja\n"
						"4 | http-download.opensuse.org-1152c701 | openSUSE 15.5-update-oss                                     | Ja      | (r ) Ja   | Ja\n"
						"5 | non-oss-addon-15.5-0                | openSUSE 15.5-non-oss                                        | Ja      | (r ) Ja   | Ja\n"
						"6 | openSUSE-Leap-15.5-1_0              | openSUSE 15.5-oss                                            | Ja      | (r ) Ja   | Ja\n"
						"8 | repo-backports-update               | Update repository of openSUSE Backports                      | Ja      | (r ) Ja   | Ja\n"
						"10 | repo-sle-update                     | Update repository with updates from SUSE Linux Enterprise 15 | Ja      | (r ) Ja   | Ja\n"
					)
				)
				result = check_manager.get("system_repositories").run(clear_cache=True)
				assert result.check_status == CheckStatus.OK
				assert result.message == "No issues found with the system repositories."
