# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# check tests
# """

# import io
# import json
# import sys
# import time
# from datetime import datetime, timedelta
# from typing import Any, Callable
# from unittest import mock

# import pytest
# import requests
# from _pytest.capture import CaptureFixture
# from mock import Mock  # type: ignore[import]
# from MySQLdb import OperationalError  # type: ignore[import]
# from opsicommon.objects import ConfigState, LocalbootProduct, OpsiClient, OpsiDepotserver, ProductOnClient, ProductOnDepot
# from redis.exceptions import ConnectionError as RedisConnectionError
# from rich.console import Console

# from opsiconfd.check.cache import check_cache_clear
# from opsiconfd.check.cli import console_health_check, process_check_result
# from opsiconfd.check.common import CheckRegistry, CheckResult, CheckStatus, PartialCheckResult
# from opsiconfd.check.main import (
# 	check_disk_usage,
# 	check_mysql,
# 	check_opsi_backup,
# 	check_redis,
# 	check_system_packages,
# 	health_check,
# )
# from opsiconfd.check.opsipackages import get_available_product_versions, get_enabled_hosts
# from opsiconfd.check.system import CHECK_SYSTEM_PACKAGES, get_repo_versions
# from opsiconfd.config import config, get_configserver_id
# from opsiconfd.redis import redis_client
# from opsiconfd.utils import NameService, UserInfo

# from .test_addon_manager import cleanup  # noqa: F401
# from .utils import (  # noqa: F401
# 	ACL_CONF_41,
# 	ADMIN_PASS,
# 	ADMIN_USER,
# 	Config,
# 	OpsiconfdTestClient,
# 	clean_mysql,
# 	get_config,
# 	get_opsi_config,
# 	sync_clean_redis,
# 	test_client,
# )
# from .utils import (
# 	config as test_config,  # noqa: F401
# )

# DEPRECATED_METHOD = "getClientIds_list"


# @pytest.fixture(autouse=True)
# def cache_clear() -> None:
# 	check_cache_clear("all")


# def captured_function_output(func: Callable, **kwargs: Any) -> str:
# 	captured_output = io.StringIO()
# 	sys.stdout = captured_output
# 	func(**kwargs)
# 	sys.stdout = sys.__stdout__
# 	return captured_output.getvalue()


# def test_upgrade_issue() -> None:
# 	result = CheckResult(check_id="test_upgrade_issue")
# 	partial_result = PartialCheckResult(check_id="test_upgrade_issue:5.0", check_status=CheckStatus.WARNING, upgrade_issue="5.0")
# 	result.add_partial_result(partial_result)
# 	partial_result = PartialCheckResult(check_id="test_upgrade_issue:5.1", check_status=CheckStatus.WARNING, upgrade_issue="5.1")
# 	result.add_partial_result(partial_result)
# 	assert result.check_status == CheckStatus.WARNING
# 	assert result.upgrade_issue == "5.0"


# def test_check_disk_usage() -> None:
# 	result = check_disk_usage(CheckRegistry().get("disk_usage").result)
# 	assert result.check_status


# def test_get_repo_versions() -> None:
# 	result = get_repo_versions()
# 	for package in CHECK_SYSTEM_PACKAGES:
# 		assert package in result

# 	packages = ("opsiconfd", "opsi-utils")
# 	with open("tests/data/check/repo.html", "r", encoding="utf-8") as html_file:
# 		html_str = html_file.read()
# 	res = requests.Response()
# 	res.status_code = 200
# 	with mock.patch("requests.Response.text", mock.PropertyMock(return_value=html_str)):
# 		result = get_repo_versions()

# 	for package in packages:
# 		assert package in result
# 		if package == "opsiconfd":
# 			assert result[package] == "4.2.0.286-1"
# 		if package == "opsi-utils":
# 			assert result[package] == "4.2.0.183-1"


# def test_check_system_packages_debian() -> None:
# 	# test up to date packages - status sould be ok and output should be green
# 	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
# 	console = Console(log_time=False, force_terminal=False, width=1000)
# 	dpkg_lines = [
# 		f"ii  {name}                         {version}                       amd64        Package description"
# 		for name, version in installed_versions.items()
# 	]

# 	class Proc:
# 		stdout = "\n".join(dpkg_lines) + "\n"

# 	with (
# 		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
# 		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
# 		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"debian"})),
# 	):
# 		result = check_system_packages(CheckRegistry().get("system_packages").result)
# 		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

# 		for name, version in installed_versions.items():
# 			assert f"Package {name!r} is up to date. Installed version: {version!r}" in captured_output

# 		assert result.message == "All packages are up to date."
# 		assert result.check_status == CheckStatus.OK

# 		for partial_result in result.partial_results:
# 			assert partial_result.check_status == "ok"
# 			assert partial_result.message == (
# 				f"Package {partial_result.details['package']!r} is up to date. Installed version: {partial_result.details['version']!r}"
# 			)

# 	# test outdated packages - status sould be warn and output sould be in yellow
# 	installed_versions = {"opsiconfd": "4.2.0.100-1", "opsi-utils": "4.2.0.100-1"}
# 	dpkg_lines = [
# 		f"ii  {name}                         {version}                       amd64        Package description"
# 		for name, version in installed_versions.items()
# 	]
# 	Proc.stdout = "\n".join(dpkg_lines) + "\n"

# 	check_cache_clear("all")
# 	with (
# 		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
# 		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
# 		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"debian"})),
# 	):
# 		result = check_system_packages(CheckRegistry().get("system_packages").result)

# 		assert result.message == "Out of 2 packages checked, 0 are not installed and 2 are out of date."
# 		assert result.check_status == CheckStatus.WARNING
# 		for partial_result in result.partial_results:
# 			assert partial_result.check_status == CheckStatus.WARNING
# 			assert partial_result.message == (
# 				f"Package {partial_result.details['package']!r} is out of date. "
# 				f"Installed version {partial_result.details['version']!r} < "
# 				f"available version {repo_versions[partial_result.details['package']]!r}"
# 			)

# 		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

# 		for name, version in installed_versions.items():
# 			assert f"Package {name!r} is out of date. Installed version {version!r}" in captured_output


# def test_check_system_packages_open_suse() -> None:
# 	console = Console(log_time=False, force_terminal=False, width=1000)
# 	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
# 	zypper_lines = [
# 		"S  | Name                 | Typ   | Version             | Arch   | Repository",
# 		"---+----------------------+-------+---------------------+--------+------------------------------",
# 	] + [
# 		f"i  | {name}            | Paket | {version} | x86_64 | opsi 4.2 (openSUSE_Leap_15.2)"
# 		for name, version in installed_versions.items()
# 	]

# 	class Proc:
# 		stdout = "\n".join(zypper_lines) + "\n"

# 	with (
# 		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
# 		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
# 		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"opensuse"})),
# 	):
# 		result = check_system_packages(CheckRegistry().get("system_packages").result)
# 		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

# 		for name, version in repo_versions.items():
# 			assert f"Package {name!r} is up to date. Installed version: {version!r}" in captured_output

# 		assert result.message == "All packages are up to date."
# 		assert result.check_status == CheckStatus.OK
# 		for partial_result in result.partial_results:
# 			assert partial_result.check_status == CheckStatus.OK
# 			assert partial_result.message == (
# 				f"Package {partial_result.details['package']!r} is up to date. Installed version: {partial_result.details['version']!r}"
# 			)


# def test_check_system_packages_redhat() -> None:
# 	console = Console(log_time=False, force_terminal=False, width=1000)
# 	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
# 	yum_lines = ["Subscription Management Repositorys werden aktualisiert.", "Installierte Pakete"] + [
# 		f"{name}.x86_64     {version}    @home_uibmz_opsi_4.2_stable " for name, version in installed_versions.items()
# 	]

# 	class Proc:
# 		stdout = "\n".join(yum_lines) + "\n"

# 	with (
# 		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
# 		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
# 		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"rhel"})),
# 	):
# 		result = check_system_packages(CheckRegistry().get("system_packages").result)
# 		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

# 		for name, version in repo_versions.items():
# 			assert f"Package {name!r} is up to date. Installed version: {version!r}" in captured_output

# 		assert result.message == "All packages are up to date."
# 		assert result.check_status == CheckStatus.OK

# 		for partial_result in result.partial_results:
# 			assert partial_result.check_status == CheckStatus.OK
# 			assert partial_result.message == (
# 				f"Package {partial_result.details['package']!r} is up to date. Installed version: {partial_result.details['version']!r}"
# 			)


# def test_get_available_product_versions() -> None:
# 	product_ids = ["opsi-script", "opsi-client-agent", "opsi-linux-client-agent", "opsi-mac-client-agent", "hwaudit", "win10", "hwinvent"]
# 	available_packages = get_available_product_versions(product_ids)
# 	assert list(available_packages) == product_ids
# 	for version in available_packages.values():
# 		assert version != "0.0"


# def _prepare_products(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	test_client.auth = (ADMIN_USER, ADMIN_PASS)
# 	depot = OpsiDepotserver(id="test-check-depot-1.opsi.test")
# 	client = OpsiClient(id="test-check-client-1.opsi.test")
# 	client.setDefaults()
# 	product = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.0.0", packageVersion="1")
# 	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_createObjects", "params": [[product.to_hash()]]}
# 	res = test_client.post("/rpc", json=rpc).json()
# 	assert "error" not in res
# 	product_on_depot = ProductOnDepot(
# 		productId=product.id,
# 		productType=product.getType(),
# 		productVersion=product.productVersion,
# 		packageVersion=product.packageVersion,
# 		depotId=depot.id,
# 	)
# 	product = LocalbootProduct(id="opsi-client-agent", productVersion="4.2.0.0", packageVersion="1")
# 	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_createObjects", "params": [[product.to_hash()]]}
# 	res = test_client.post("/rpc", json=rpc).json()
# 	assert "error" not in res
# 	product_on_client = ProductOnClient(
# 		productId=product.id,
# 		productVersion=product.productVersion,
# 		packageVersion=product.packageVersion,
# 		productType=product.getType(),
# 		clientId=client.id,
# 		installationStatus="installed",
# 	)

# 	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[depot.to_hash(), client.to_hash()]]}
# 	res = test_client.post("/rpc", json=rpc).json()
# 	assert "error" not in res

# 	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_createObjects", "params": [[product_on_depot.to_hash()]]}
# 	res = test_client.post("/rpc", json=rpc).json()
# 	assert "error" not in res

# 	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_createObjects", "params": [[product_on_client.to_hash()]]}
# 	res = test_client.post("/rpc", json=rpc).json()
# 	assert "error" not in res


# def test_check_product_on_depots(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	_prepare_products(test_client=test_client)
# 	result = CheckRegistry().get("products_on_depots").run(use_cache=False)
# 	# print(result)
# 	assert result.check_status == CheckStatus.ERROR
# 	assert "1 are out of date" in result.message
# 	assert result.upgrade_issue == "4.3"
# 	found = 0
# 	for partial_result in result.partial_results:
# 		# print(partial_result)
# 		if partial_result.check_id == "products_on_depots:test-check-depot-1.opsi.test:opsi-script":
# 			found += 1
# 			assert partial_result.check_status == CheckStatus.ERROR
# 			assert "not installed" in partial_result.message
# 			assert partial_result.upgrade_issue == "4.3"
# 		if partial_result.check_id == "products_on_depots:test-check-depot-1.opsi.test:opsi-client-agent":
# 			found += 1
# 			assert partial_result.check_status == CheckStatus.ERROR
# 			assert "is outdated" in partial_result.message
# 			assert partial_result.upgrade_issue == "4.3"
# 	assert found == 2


# def test_check_product_on_clients(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	_prepare_products(test_client=test_client)
# 	result = CheckRegistry().get("products_on_clients").run(use_cache=False)
# 	# print(result)
# 	assert result.check_status == CheckStatus.ERROR
# 	assert "are out of date" in result.message
# 	assert result.upgrade_issue == "4.3"

# 	found = 0
# 	for partial_result in result.partial_results:
# 		# print(partial_result)
# 		if partial_result.check_id == "products_on_clients:test-check-client-1.opsi.test:opsi-client-agent":
# 			found += 1
# 			assert partial_result.check_status == CheckStatus.ERROR
# 			assert "is outdated" in partial_result.message
# 			assert partial_result.upgrade_issue == "4.3"
# 	assert found == 1


# def test_health_check() -> None:
# 	sync_clean_redis()
# 	results = list(health_check())
# 	assert len(results) == 20
# 	for result in results:
# 		print(result.check_id, result.check_status)
# 		assert result.check_status


# def test_check_licenses(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	result = CheckRegistry().get("licenses").run(use_cache=False)
# 	assert result.check_status == "ok"
# 	assert result.partial_results is not None


# def test_check_opsi_config(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [True]]}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	assert res.status_code == 200

# 	result = CheckRegistry().get("opsi_config").run(use_cache=False)
# 	print(result)
# 	assert result.check_status == CheckStatus.OK
# 	assert result.message == "No issues found in the opsi configuration."
# 	assert len(result.partial_results) == 1
# 	partial_result = result.partial_results[0]
# 	assert partial_result.message == "Configuration opsiclientd.global.verify_server_cert is set to default."

# 	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [False]]}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	assert res.status_code == 200

# 	result = CheckRegistry().get("opsi_config").run(use_cache=False)
# 	assert result.check_status == CheckStatus.WARNING
# 	assert result.message == "1 issues found in the opsi configuration."
# 	assert len(result.partial_results) == 1
# 	partial_result = result.partial_results[0]
# 	assert partial_result.message == "Configuration opsiclientd.global.verify_server_cert is set to [False] - default is [True]."

# 	rpc = {"id": 1, "method": "config_delete", "params": ["opsiclientd.global.verify_server_cert"]}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	assert res.status_code == 200

# 	result = CheckRegistry().get("opsi_config").run(use_cache=False)
# 	assert result.check_status == CheckStatus.ERROR
# 	assert result.message == "1 issues found in the opsi configuration."
# 	assert len(result.partial_results) == 1
# 	partial_result = result.partial_results[0]
# 	assert partial_result.message == "Configuration opsiclientd.global.verify_server_cert does not exist."


# def test_checks_and_skip_checks() -> None:
# 	with get_config({"checks": ["redis", "mysql", "ssl"]}):
# 		list_of_checks = list(health_check())
# 		assert len(list_of_checks) == 3

# 	with get_config({"skip_checks": ["redis", "mysql", "ssl"]}):
# 		list_of_checks = list(health_check())
# 		assert len(list_of_checks) == 17


# def test_check_opsi_users() -> None:
# 	result = CheckRegistry().get("users").run(use_cache=False)
# 	assert result.check_status == CheckStatus.OK

# 	# If the server is part of a domain and the opsi users are local users, a warning should be issued.
# 	with (
# 		mock.patch(
# 			"opsiconfd.check.users.get_user_passwd_details",
# 			return_value=(
# 				[
# 					UserInfo(
# 						username="pcpatch",
# 						uid=1000,
# 						gid=1000,
# 						gecos="PCPatch",
# 						home="/home/pcpatch",
# 						shell="/bin/bash",
# 						service=NameService(NameService.FILES),
# 					)
# 				]
# 			),
# 		),
# 		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.FILES, NameService.SSS])),
# 	):
# 		result = CheckRegistry().get("users").run(use_cache=False)
# 		assert result.check_status == CheckStatus.WARNING

# 	# If the server  is part of a domain and the opsi users are only domain users, no warning should be issued.
# 	with (
# 		mock.patch(
# 			"opsiconfd.check.users.get_user_passwd_details",
# 			return_value=(
# 				[
# 					UserInfo(
# 						username="pcpatch",
# 						uid=1000,
# 						gid=1000,
# 						gecos="PCPatch",
# 						home="/home/pcpatch",
# 						shell="/bin/bash",
# 						service=NameService.WINBIND,
# 					)
# 				]
# 			),
# 		),
# 		mock.patch(
# 			"opsiconfd.check.users.get_passwd_services", return_value=([NameService.FILES, NameService.SYSTEMD, NameService.WINBIND])
# 		),
# 	):
# 		result = CheckRegistry().get("users").run(use_cache=False)
# 		assert result.check_status == CheckStatus.OK

# 	# If the server is part of a domain and the opsi users are local and domain users, an error should be issued.
# 	with (
# 		mock.patch(
# 			"opsiconfd.check.users.get_user_passwd_details",
# 			return_value=(
# 				[
# 					UserInfo(
# 						username="pcpatch",
# 						uid=1000,
# 						gid=1000,
# 						gecos="PCPatch",
# 						home="/home/pcpatch",
# 						shell="/bin/bash",
# 						service=NameService.LDAP,
# 					),
# 					UserInfo(
# 						username="pcpatch",
# 						uid=111111,
# 						gid=111111,
# 						gecos="PCPatch",
# 						home="/home/pcpatch",
# 						shell="/bin/bash",
# 						service=NameService.COMPAT,
# 					),
# 				]
# 			),
# 		),
# 		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.COMPAT, NameService.SYSTEMD, NameService.LDAP])),
# 	):
# 		result = CheckRegistry().get("users").run(use_cache=False)
# 		assert result.check_status == CheckStatus.ERROR

# 	# If the server is not part of a domain and the opsi users are local users, no warning should be issued.
# 	with (
# 		mock.patch(
# 			"opsiconfd.check.users.get_user_passwd_details",
# 			return_value=(
# 				[
# 					UserInfo(
# 						username="pcpatch",
# 						uid=1000,
# 						gid=1000,
# 						gecos="PCPatch",
# 						home="/home/pcpatch",
# 						shell="/bin/bash",
# 						service=NameService.COMPAT,
# 					)
# 				]
# 			),
# 		),
# 		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.COMPAT, NameService.SYSTEMD])),
# 	):
# 		result = CheckRegistry().get("users").run(use_cache=False)
# 		assert result.check_status == CheckStatus.OK

# 	# check for missing user
# 	with get_opsi_config([{"category": "depot_user", "config": "username", "value": "pcpatch-local"}]):
# 		result = CheckRegistry().get("users").run(use_cache=False)
# 		assert result.check_status == CheckStatus.ERROR
# 		assert result.message == "A required user does not exist."


# def test_check_system_repos() -> None:
# 	# Test debian 10 with debian 11 repository and debian 10 repository
# 	with mock.patch("opsiconfd.check.system.linux_distro_id") as mock_distro_id:
# 		mock_distro_id.return_value = "debian"
# 		with mock.patch("opsiconfd.check.system.linux_distro_version_id") as mock_distro_version:
# 			mock_distro_version.return_value = "10"
# 			with mock.patch("opsiconfd.check.system.run") as mock_run:
# 				mock_run.return_value = Mock(
# 					stdout=(
# 						"Package files:\n"
# 						"100 /var/lib/dpkg/status\n"
# 						"	release a=now\n"
# 						"500 https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.3:/stable/Debian_11  Packages\n"
# 						"	release o=obs://build.opensuse.org/home:uibmz:opsi:4.3:stable/Debian_11,n=Debian_11,l=home:uibmz:opsi:4.3:stable,c=\n"
# 						"	origin download.opensuse.org\n"
# 						"500 https://apt.grafana.com stable/main amd64 Packages\n"
# 						"	release o=. stable,a=stable,n=stable,l=. stable,c=main,b=amd64\n"
# 						"	origin apt.grafana.com\n"
# 						"Pinned packages:\n"
# 					)
# 				)
# 				result = CheckRegistry().get("system_repositories").run(use_cache=False)
# 				assert result.check_status == CheckStatus.ERROR
# 				assert (
# 					result.message
# 					== "System and opsi repositories are incompatible. System 'debian 10' using repository: https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.3:/stable/Debian_11"
# 				)

# 		with mock.patch("opsiconfd.check.system.run") as mock_run:
# 			mock_run.return_value = Mock(
# 				stdout=(
# 					"Package files:\n"
# 					"100 /var/lib/dpkg/status\n"
# 					"	release a=now\n"
# 					"500 https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.3:/stable/Debian_10  Packages\n"
# 					"	release o=obs://build.opensuse.org/home:uibmz:opsi:4.3:stable/Debian_11,n=Debian_10,l=home:uibmz:opsi:4.3:stable,c=\n"
# 					"	origin download.opensuse.org\n"
# 					"500 https://apt.grafana.com stable/main amd64 Packages\n"
# 					"	release o=. stable,a=stable,n=stable,l=. stable,c=main,b=amd64\n"
# 					"	origin apt.grafana.com\n"
# 					"Pinned packages:\n"
# 				)
# 			)
# 			result = CheckRegistry().get("system_repositories").run(use_cache=False)
# 			assert result.check_status == CheckStatus.OK
# 			assert result.message == "No issues found with the system repositories."
# 	# test rocky 9 with rocky 8 repository and rocky 9 repository
# 	with mock.patch("opsiconfd.check.system.linux_distro_id") as mock_distro_id:
# 		mock_distro_id.return_value = "rocky"
# 		with mock.patch("opsiconfd.check.system.linux_distro_version_id") as mock_distro_version:
# 			mock_distro_version.return_value = "9"
# 			with mock.patch("opsiconfd.check.system.run") as mock_run:
# 				mock_run.return_value = Mock(
# 					stdout=(
# 						"Paketquellenkennung        Paketquellenname\n"
# 						"appstream                  Rocky Linux 9 - AppStream\n"
# 						"baseos                     Rocky Linux 9 - BaseOS\n"
# 						"epel                       Extra Packages for Enterprise Linux 9 - x86_64\n"
# 						"epel-cisco-openh264        Extra Packages for Enterprise Linux 9 openh264 (From Cisco) - x86_64\n"
# 						"extras                     Rocky Linux 9 - Extras\n"
# 						"grafana                    grafana\n"
# 						"home_uibmz_opsi_4.3_stable opsi 4.3 stable (RockyLinux_8)\n"
# 					)
# 				)
# 				result = CheckRegistry().get("system_repositories").run(use_cache=False)
# 				assert result.check_status == CheckStatus.ERROR
# 				assert (
# 					result.message
# 					== "System and opsi repositories are incompatible. System 'rocky 9' using repository: home_uibmz_opsi_4.3_stable opsi 4.3 stable (RockyLinux_8)"
# 				)
# 			with mock.patch("opsiconfd.check.system.run") as mock_run:
# 				mock_run.return_value = Mock(
# 					stdout=(
# 						"Paketquellenkennung        Paketquellenname\n"
# 						"appstream                  Rocky Linux 9 - AppStream\n"
# 						"baseos                     Rocky Linux 9 - BaseOS\n"
# 						"epel                       Extra Packages for Enterprise Linux 9 - x86_64\n"
# 						"epel-cisco-openh264        Extra Packages for Enterprise Linux 9 openh264 (From Cisco) - x86_64\n"
# 						"extras                     Rocky Linux 9 - Extras\n"
# 						"grafana                    grafana\n"
# 						"home_uibmz_opsi_4.3_stable opsi 4.3 stable (RockyLinux_9)\n"
# 					)
# 				)
# 				result = CheckRegistry().get("system_repositories").run(use_cache=False)
# 				assert result.check_status == CheckStatus.OK
# 				assert result.message == "No issues found with the system repositories."
# 	# Test openSUSE 15.5 with openSUSE 15.4 repository and openSUSE 15.5 repository
# 	with mock.patch("opsiconfd.check.system.linux_distro_id") as mock_distro_id:
# 		mock_distro_id.return_value = "opensuse-leap"
# 		with mock.patch("opsiconfd.check.system.linux_distro_version_id") as mock_distro_version:
# 			mock_distro_version.return_value = "15.5"
# 			with mock.patch("opsiconfd.check.system.run") as mock_run:
# 				mock_run.return_value = Mock(
# 					stdout=(
# 						"Die Repository-Prioritäten sind ohne Effekt. Alle aktivierten Repositorys teilen sich die gleiche Priorität.\n"
# 						" \n"
# 						"#  | Alias                               | Name                                                         | Enabled | GPG Check | Refresh\n"
# 						"---+-------------------------------------+--------------------------------------------------------------+---------+-----------+--------\n"
# 						"1 | grafana                             | grafana                                                      | Ja      | (r ) Ja   | Nein\n"
# 						"2 | home_uibmz_opsi_4.3_stable          | opsi 4.3 stable (openSUSE_Leap_15.4)                         | Ja      | ( p) Ja   | Nein\n"
# 						"3 | http-download.opensuse.org-0b97f368 | openSUSE 15.5-update-non-oss                                 | Ja      | (r ) Ja   | Ja\n"
# 						"4 | http-download.opensuse.org-1152c701 | openSUSE 15.5-update-oss                                     | Ja      | (r ) Ja   | Ja\n"
# 						"5 | non-oss-addon-15.5-0                | openSUSE 15.5-non-oss                                        | Ja      | (r ) Ja   | Ja\n"
# 						"6 | openSUSE-Leap-15.5-1_0              | openSUSE 15.5-oss                                            | Ja      | (r ) Ja   | Ja\n"
# 						"8 | repo-backports-update               | Update repository of openSUSE Backports                      | Ja      | (r ) Ja   | Ja\n"
# 						"10 | repo-sle-update                     | Update repository with updates from SUSE Linux Enterprise 15 | Ja      | (r ) Ja   | Ja\n"
# 					)
# 				)
# 				result = CheckRegistry().get("system_repositories").run(use_cache=False)
# 				assert result.check_status == CheckStatus.ERROR
# 				assert (
# 					result.message
# 					== "System and opsi repositories are incompatible. System 'opensuse-leap 15.5' using repository: opsi 4.3 stable (openSUSE_Leap_15.4)"
# 				)
# 			with mock.patch("opsiconfd.check.system.run") as mock_run:
# 				mock_run.return_value = Mock(
# 					stdout=(
# 						"Die Repository-Prioritäten sind ohne Effekt. Alle aktivierten Repositorys teilen sich die gleiche Priorität.\n"
# 						" \n"
# 						"#  | Alias                               | Name                                                         | Enabled | GPG Check | Refresh\n"
# 						"---+-------------------------------------+--------------------------------------------------------------+---------+-----------+--------\n"
# 						"1 | grafana                             | grafana                                                      | Ja      | (r ) Ja   | Nein\n"
# 						"2 | home_uibmz_opsi_4.3_stable          | opsi 4.3 stable (openSUSE_Leap_15.5)                         | Ja      | ( p) Ja   | Nein\n"
# 						"3 | http-download.opensuse.org-0b97f368 | openSUSE 15.5-update-non-oss                                 | Ja      | (r ) Ja   | Ja\n"
# 						"4 | http-download.opensuse.org-1152c701 | openSUSE 15.5-update-oss                                     | Ja      | (r ) Ja   | Ja\n"
# 						"5 | non-oss-addon-15.5-0                | openSUSE 15.5-non-oss                                        | Ja      | (r ) Ja   | Ja\n"
# 						"6 | openSUSE-Leap-15.5-1_0              | openSUSE 15.5-oss                                            | Ja      | (r ) Ja   | Ja\n"
# 						"8 | repo-backports-update               | Update repository of openSUSE Backports                      | Ja      | (r ) Ja   | Ja\n"
# 						"10 | repo-sle-update                     | Update repository with updates from SUSE Linux Enterprise 15 | Ja      | (r ) Ja   | Ja\n"
# 					)
# 				)
# 				result = CheckRegistry().get("system_repositories").run(use_cache=False)
# 				assert result.check_status == CheckStatus.OK
# 				assert result.message == "No issues found with the system repositories."


# def test_check_opsi_config_checkmk(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [True]]}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	assert res.status_code == 200

# 	result = CheckRegistry().get("opsi_config").run(use_cache=False)
# 	checkmk = result.to_checkmk()
# 	assert checkmk.startswith("0")
# 	assert result.check_name in checkmk
# 	assert "No issues found in the opsi configuration." in checkmk
# 	assert "Configuration opsiclientd.global.verify_server_cert is set to default." in checkmk

# 	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [False]]}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	assert res.status_code == 200

# 	result = CheckRegistry().get("opsi_config").run(use_cache=False)
# 	checkmk = result.to_checkmk()
# 	assert checkmk.startswith("1")
# 	assert "1 issues found in the opsi configuration." in checkmk
# 	assert "Configuration opsiclientd.global.verify_server_cert is set to [False] - default is [True]." in checkmk

# 	rpc = {"id": 1, "method": "config_delete", "params": ["opsiclientd.global.verify_server_cert"]}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	assert res.status_code == 200

# 	result = CheckRegistry().get("opsi_config").run(use_cache=False)
# 	checkmk = result.to_checkmk()
# 	assert checkmk.startswith("2")
# 	assert "1 issues found in the opsi configuration." in checkmk
# 	assert "Configuration opsiclientd.global.verify_server_cert does not exist." in checkmk


# @pytest.mark.parametrize("format", ("cli", "json", "checkmk"))
# def test_check_console_health_check(capsys: CaptureFixture[str], format: str) -> None:
# 	with get_config({"upgrade_check": False, "documentation": False, "detailed": True, "format": format}):
# 		console_health_check()
# 		captured = capsys.readouterr()
# 		if format == "json":
# 			data = json.loads(captured.out)
# 			assert isinstance(data, dict)
# 			assert len(data) > 10
# 			assert data["check_status"]
# 			assert data["summary"]
# 			assert isinstance(data["system_repositories"], dict)
# 			assert data["system_repositories"]["check_id"]
# 			assert data["system_repositories"]["check_description"]
# 		elif format == "checkmk":
# 			services = captured.out.split("\n")
# 			assert len(services) > 10
# 			status, _ = services[0].split(" ", 1)
# 			assert 0 <= int(status) <= 2
# 		else:
# 			assert "● Redis Server" in captured.out


# def test_check_downtime(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	test_client.auth = (ADMIN_USER, ADMIN_PASS)
# 	client = OpsiClient(id="test-check-client-1.opsi.test")
# 	client.setDefaults()
# 	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client.to_hash()]]}
# 	res = test_client.post("/rpc", json=rpc).json()
# 	assert "error" not in res

# 	rpc = {
# 		"id": 1,
# 		"method": "host_getIdents",
# 		"params": [],
# 	}
# 	res = test_client.post("/rpc", json=rpc)
# 	hosts = res.json().get("result")

# 	# all host should be enabled
# 	enabled_hosts = get_enabled_hosts()
# 	assert hosts == enabled_hosts

# 	# set downtime for client 1 for tomorrow and check if it is disabled
# 	tomorrow = datetime.now() + timedelta(days=1)
# 	downtime = ConfigState(configId="opsi.check.downtime.end", objectId=client.id, values=[tomorrow.isoformat()])
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_updateObjects",
# 		"params": [[downtime.to_json()]],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

# 	enabled_hosts = get_enabled_hosts()
# 	assert len(hosts) > len(enabled_hosts)

# 	# set downtime for client 1 from yesterday to tomorrow and check if it is disabled
# 	yesterday = datetime.now() - timedelta(days=1)
# 	downtime = ConfigState(configId="opsi.check.downtime.end", objectId=client.id, values=[tomorrow.isoformat()])
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_updateObjects",
# 		"params": [[downtime.to_json()]],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

# 	enabled_hosts = get_enabled_hosts()
# 	assert len(hosts) > len(enabled_hosts)

# 	# set downtime for client 1 from tomorrow to 2 days from now and check if it is enabled
# 	two_days = datetime.now() + timedelta(days=2)
# 	downtime = ConfigState(configId="opsi.check.downtime.end", objectId=client.id, values=[two_days.isoformat()])
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_updateObjects",
# 		"params": [[downtime.to_json()]],
# 	}
# 	downtime = ConfigState(configId="opsi.check.downtime.start", objectId=client.id, values=[tomorrow.isoformat()])
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_updateObjects",
# 		"params": [[downtime.to_json()]],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

# 	enabled_hosts = get_enabled_hosts()
# 	assert len(hosts) == len(enabled_hosts)

# 	rpc = {
# 		"id": 1,
# 		"method": "configState_delete",
# 		"params": ["opsi.check.downtime.start", client.id],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

# 	# set downtime for client 1 for yesterday and check if it is enabled
# 	downtime = ConfigState(configId="opsi.check.downtime.end", objectId=client.id, values=[yesterday.isoformat()])
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_updateObjects",
# 		"params": [[downtime.to_json()]],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

# 	enabled_hosts = get_enabled_hosts()
# 	assert len(hosts) == len(enabled_hosts)

# 	# set opsi.check.enabled to false for client 1 and check if it is disabled
# 	disable = ConfigState(configId="opsi.check.enabled", objectId=client.id, values=[False])
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_updateObjects",
# 		"params": [[disable.to_json()]],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

# 	enabled_hosts = get_enabled_hosts()
# 	assert len(hosts) > len(enabled_hosts)

# 	# set opsi.check.enabled to true for client 1 and check if it is enabled
# 	enable = ConfigState(configId="opsi.check.enabled", objectId=client.id, values=[True])
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_updateObjects",
# 		"params": [[enable.to_json()]],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

# 	enabled_hosts = get_enabled_hosts()
# 	assert len(hosts) == len(enabled_hosts)

# 	# set opsi.check.enabled to false for config server and check if all hosts are disabled
# 	# delete downtime and enable config for client 1
# 	config_server = get_configserver_id()
# 	disable_server = ConfigState(configId="opsi.check.enabled", objectId=config_server, values=[False])
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_updateObjects",
# 		"params": [[disable_server.to_json()]],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_delete",
# 		"params": ["opsi.check.enabled", client.id],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_delete",
# 		"params": ["opsi.check.downtime.end", client.id],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_delete",
# 		"params": ["opsi.check.downtime.start", client.id],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	enabled_hosts = get_enabled_hosts()
# 	assert len(enabled_hosts) == 0

# 	# delete config state for config server and check if all hosts are enabled
# 	rpc = {
# 		"id": 1,
# 		"method": "configState_delete",
# 		"params": ["opsi.check.enabled", config_server],
# 	}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	enabled_hosts = get_enabled_hosts()
# 	assert hosts == enabled_hosts


# def test_check_backup(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	sync_clean_redis()
# 	# backup check should fail. No backup was created.

# 	result = CheckRegistry().get("opsi_backup").run(use_cache=False)
# 	assert result.check_status == CheckStatus.ERROR

# 	# create a backup
# 	rpc = {"id": 1, "method": "service_createBackup", "params": [False, False, False]}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	assert res.status_code == 200

# 	# backup check should pass. A backup was created.
# 	result = CheckRegistry().get("opsi_backup").run(use_cache=False)
# 	assert result.check_status == CheckStatus.OK

# 	redis = redis_client()
# 	# remove backup key so check should fail again
# 	redis.delete(config.redis_key("stats") + ":backup")

# 	time.sleep(1)

# 	result = CheckRegistry().get("opsi_backup").run(use_cache=False)
# 	assert result.check_status == CheckStatus.ERROR


# def test_check_cache(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
# 	sync_clean_redis()
# 	# backup check should fail. No backup was created.

# 	result = check_opsi_backup(check_cache_clear("opsi_backup"))
# 	assert result.check_status == CheckStatus.ERROR

# 	with mock.patch(
# 		"opsiconfd.check.mysql.MySQLConnection.connect",
# 		side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'),
# 	):
# 		result = check_mysql(CheckRegistry().get("mysql").result)
# 		assert result.check_status == CheckStatus.ERROR

# 	with mock.patch("opsiconfd.check.redis.redis_client", side_effect=RedisConnectionError("Redis test error")):
# 		result = check_redis(CheckRegistry().get("redis").result)
# 		assert result.check_status == CheckStatus.ERROR

# 	# Create a backup
# 	rpc = {"id": 1, "method": "service_createBackup", "params": [False, False, False]}
# 	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
# 	assert res.status_code == 200

# 	# Redis and mysql check should fail. Backup cache should be reset after calling create backup.
# 	result = check_redis(CheckRegistry().get("redis").result)
# 	assert result.check_status == CheckStatus.ERROR
# 	result = check_opsi_backup(CheckRegistry().get("opsi_backup").result)
# 	assert result.check_status == CheckStatus.OK
# 	result = check_mysql(CheckRegistry().get("mysql").result)
# 	assert result.check_status == CheckStatus.ERROR

# 	# Clear backup cache
# 	check_cache_clear("opsi_backup")

# 	# Backup check should pass. A backup was created. Mysql check should fail. Cache is not cleared.
# 	result = check_redis(CheckRegistry().get("redis").result)
# 	assert result.check_status == CheckStatus.ERROR
# 	result = check_opsi_backup(CheckRegistry().get("opsi_backup").result)
# 	assert result.check_status == CheckStatus.OK
# 	result = check_mysql(CheckRegistry().get("mysql").result)
# 	assert result.check_status == CheckStatus.ERROR

# 	# Clear cache. Backup and mysql check should pass.
# 	check_cache_clear("all")
# 	result = check_redis(CheckRegistry().get("redis").result)
# 	assert result.check_status == CheckStatus.OK
# 	result = check_opsi_backup(CheckRegistry().get("opsi_backup").result)
# 	assert result.check_status == CheckStatus.OK
# 	result = check_mysql(CheckRegistry().get("mysql").result)
# 	assert result.check_status == CheckStatus.OK
