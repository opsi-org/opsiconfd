# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
check tests
"""


import io
import pwd
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable
from unittest import mock
from warnings import catch_warnings, simplefilter

import requests
from MySQLdb import OperationalError  # type: ignore[import]
from opsicommon.objects import (
	LocalbootProduct,
	OpsiClient,
	OpsiDepotserver,
	ProductOnClient,
	ProductOnDepot,
)
from redis.exceptions import ConnectionError as RedisConnectionError
from rich.console import Console

from opsiconfd.check import (
	CHECK_SYSTEM_PACKAGES,
	CheckResult,
	CheckStatus,
	PartialCheckResult,
	check_depotservers,
	check_deprecated_calls,
	check_disk_usage,
	check_ldap_connection,
	check_mysql,
	check_opsi_config,
	check_opsi_licenses,
	check_opsiconfd_config,
	check_product_on_clients,
	check_product_on_depots,
	check_redis,
	check_run_as_user,
	check_system_packages,
	get_available_product_versions,
	get_repo_versions,
	health_check,
	process_check_result,
)
from opsiconfd.config import config, opsi_config

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	get_config,
	get_opsi_config,
	sync_clean_redis,
	sync_redis_client,
	test_client,
)

DEPRECATED_METHOD = "getClientIds_list"


def captured_function_output(func: Callable, **kwargs: Any) -> str:
	captured_output = io.StringIO()
	sys.stdout = captured_output
	func(**kwargs)
	sys.stdout = sys.__stdout__
	return captured_output.getvalue()


def test_upgrade_issue() -> None:
	result = CheckResult(check_id="test_upgrade_issue")
	partial_result = PartialCheckResult(check_id="test_upgrade_issue:5.0", check_status=CheckStatus.WARNING, upgrade_issue="5.0")
	result.add_partial_result(partial_result)
	partial_result = PartialCheckResult(check_id="test_upgrade_issue:5.1", check_status=CheckStatus.WARNING, upgrade_issue="5.1")
	result.add_partial_result(partial_result)
	assert result.check_status == CheckStatus.WARNING
	assert result.upgrade_issue == "5.0"


def test_check_disk_usage() -> None:
	result = check_disk_usage()
	assert result.check_status


def test_check_run_as_user() -> None:
	result = check_run_as_user()
	assert result.check_status == CheckStatus.OK

	user = pwd.getpwnam(config.run_as_user)

	class MockUser:  # pylint: disable=too-few-public-methods
		pw_name = user.pw_name
		pw_gid = user.pw_gid
		pw_dir = "/wrong/home"

	with mock.patch("opsiconfd.check.pwd.getpwnam", mock.PropertyMock(return_value=MockUser())):
		result = check_run_as_user()
		assert result.check_status == CheckStatus.WARNING
		assert result.partial_results[0].details["home_directory"] == "/wrong/home"

	with mock.patch("opsiconfd.check.os.getgrouplist", mock.PropertyMock(return_value=(1, 2, 3))):
		result = check_run_as_user()
		assert result.check_status == CheckStatus.ERROR
		assert result.partial_results[1].message == "User 'opsiconfd' is not a member of group 'shadow'."
		assert (
			result.partial_results[2].message == f"User 'opsiconfd' is not a member of group '{opsi_config.get('groups', 'admingroup')}'."
		)
		assert (
			result.partial_results[3].message
			== f"User 'opsiconfd' is not a member of group '{opsi_config.get('groups', 'fileadmingroup')}'."
		)


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
				assert partial_result.message == "Log level setting 'log-level-stderr=SECRET' is much to high for productive use."
				assert partial_result.details == {"config": "log-level-stderr", "value": 9}
			elif partial_result.check_id == "opsiconfd_config:debug-options":
				assert partial_result.check_status == CheckStatus.ERROR
				assert partial_result.message == "The following debug options are set: rpc-log, asyncio."
				assert partial_result.details == {
					"config": "debug-options",
					"value": ["rpc-log", "asyncio"],
				}
				ids_found += 1
		assert ids_found == 2


def test_check_depotservers(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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
	console = Console(log_time=False, force_terminal=False, width=1000)
	result = check_redis()
	captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
	assert "Redis is running and RedisTimeSeries is loaded." in captured_output
	assert result.check_status == "ok"


def test_check_redis_error() -> None:
	with mock.patch("opsiconfd.redis.get_redis_connection", side_effect=RedisConnectionError("Redis test error")):
		console = Console(log_time=False, force_terminal=False, width=1000)
		result = check_redis()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		assert "Cannot connect to Redis" in captured_output
		assert result.check_status == "error"
		assert result.message == "Cannot connect to Redis: Redis test error"


def test_check_mysql() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False, force_terminal=False, width=1000)
	result = check_mysql()
	captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

	assert "Connection to MySQL is working." in captured_output
	assert result.check_status == "ok"
	assert result.message == "Connection to MySQL is working."


def test_check_mysql_error() -> None:  # pylint: disable=redefined-outer-name
	with mock.patch(
		"opsiconfd.check.MySQLConnection.connect",
		side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'),
	):
		console = Console(log_time=False, force_terminal=False, width=1000)
		result = check_mysql()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		assert '2005 - "Unknown MySQL server host bla (-3)"' in captured_output
		assert result.check_status == "error"
		assert result.message == '2005 - "Unknown MySQL server host bla (-3)"'


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


def test_check_system_packages_debian() -> None:  # pylint: disable=redefined-outer-name
	# test up to date packages - status sould be ok and output should be green
	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	console = Console(log_time=False, force_terminal=False, width=1000)
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
				f"Package {partial_result.details['package']!r} is out of date. "
				f"Installed version {partial_result.details['version']!r} < "
				f"available version {repo_versions[partial_result.details['package']]!r}"
			)

		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in installed_versions.items():
			assert f"Package {name!r} is out of date. Installed version {version!r}" in captured_output


def test_check_system_packages_open_suse() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False, force_terminal=False, width=1000)
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


def test_check_system_packages_redhat() -> None:  # pylint: disable=redefined-outer-name
	console = Console(log_time=False, force_terminal=False, width=1000)
	repo_versions = installed_versions = {"opsiconfd": "4.2.0.200-1", "opsi-utils": "4.2.0.180-1"}
	yum_lines = ["Subscription Management Repositorys werden aktualisiert.", "Installierte Pakete"] + [
		f"{name}.x86_64     {version}    @home_uibmz_opsi_4.2_stable " for name, version in installed_versions.items()
	]

	class Proc:  # pylint: disable=too-few-public-methods
		stdout = "\n".join(yum_lines) + "\n"

	with (
		mock.patch("opsiconfd.check.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.run", mock.PropertyMock(return_value=Proc())),
		mock.patch("opsicommon.system.info.linux_distro_id_like", mock.PropertyMock(return_value={"rhel"})),
	):
		result = check_system_packages()
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


def _prepare_products(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	depot = OpsiDepotserver(id="test-check-depot-1.opsi.test")
	client = OpsiClient(id="test-check-client-1.opsi.test")
	client.setDefaults()
	product = LocalbootProduct(id="opsi-client-agent", productVersion="4.2.0.0", packageVersion="1")
	product_on_depot = ProductOnDepot(
		productId=product.id,
		productType=product.getType(),
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		depotId=depot.id,
	)
	product_on_client = ProductOnClient(
		productId=product.id,
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		productType=product.getType(),
		clientId=client.id,
		installationStatus="installed",
	)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[depot.to_hash(), client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_createObjects", "params": [[product.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_createObjects", "params": [[product_on_depot.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_createObjects", "params": [[product_on_client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res


def test_check_product_on_depots(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	_prepare_products(test_client=test_client)
	result = check_product_on_depots()
	# print(result)
	assert result.check_status == CheckStatus.ERROR
	assert "1 are out of date" in result.message
	assert result.upgrade_issue == "4.3"
	found = 0
	for partial_result in result.partial_results:
		# print(partial_result)
		if partial_result.check_id == "product_on_depots:test-check-depot-1.opsi.test:opsi-script":
			found += 1
			assert partial_result.check_status == CheckStatus.ERROR
			assert "not installed" in partial_result.message
			assert partial_result.upgrade_issue == "4.3"
		if partial_result.check_id == "product_on_depots:test-check-depot-1.opsi.test:opsi-client-agent":
			found += 1
			assert partial_result.check_status == CheckStatus.ERROR
			assert "is outdated" in partial_result.message
			assert partial_result.upgrade_issue == "4.3"
	assert found == 2


def test_check_product_on_clients(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	_prepare_products(test_client=test_client)
	result = check_product_on_clients()
	# print(result)
	assert result.check_status == CheckStatus.ERROR
	assert "are out of date" in result.message
	assert result.upgrade_issue == "4.3"
	found = 0
	for partial_result in result.partial_results:
		# print(partial_result)
		if partial_result.check_id == "product_on_clients:test-check-client-1.opsi.test:opsi-client-agent":
			found += 1
			assert partial_result.check_status == CheckStatus.ERROR
			assert "is outdated" in partial_result.message
			assert partial_result.upgrade_issue == "4.3"
	assert found == 1


def test_health_check() -> None:
	sync_clean_redis()
	results = list(health_check())
	assert len(results) == 13
	for result in results:
		print(result.check_id, result.check_status)
		assert result.check_status


def test_check_deprecated_calls(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	sync_clean_redis()
	console = Console(log_time=False, force_terminal=False, width=1000)
	result = check_deprecated_calls()
	captured_output = captured_function_output(process_check_result, result=result, console=console)
	assert "No deprecated method calls found." in captured_output
	assert result.check_status == CheckStatus.OK

	rpc = {"id": 1, "method": DEPRECATED_METHOD, "params": []}
	current_dt = datetime.utcnow().astimezone(timezone.utc)
	with mock.patch("opsiconfd.application.jsonrpc.AWAIT_STORE_RPC_INFO", True), catch_warnings():
		simplefilter("ignore")
		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	assert res.status_code == 200

	result = check_deprecated_calls()

	# print(result)
	assert result.check_status == CheckStatus.WARNING
	assert len(result.partial_results) == 1
	partial_result = result.partial_results[0]
	# print(partial_result)
	assert partial_result.details["method"] == DEPRECATED_METHOD
	assert partial_result.details["calls"] == "1"
	assert partial_result.details["last_call"]
	assert partial_result.details["drop_version"] == "4.4"
	assert partial_result.upgrade_issue == "4.4"
	last_call_dt = datetime.fromisoformat(partial_result.details["last_call"]).astimezone(timezone.utc)
	assert (last_call_dt - current_dt).total_seconds() < 3
	assert isinstance(partial_result.details["applications"], list)
	assert partial_result.details["applications"] == ["testclient"]

	captured_output = captured_function_output(process_check_result, result=result, console=console, check_version="4.4", detailed=True)
	assert "The method will be dropped with opsiconfd version 4.4" in captured_output

	# test key expires and method is removed from set
	redis_prefix_stats = config.redis_key("stats")
	with sync_redis_client() as redis_client:
		methods = redis_client.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
		assert len(methods) == 1
		redis_client.expire(f"{redis_prefix_stats}:rpcs:deprecated:{DEPRECATED_METHOD}:count", 1)
	time.sleep(5)
	result = check_deprecated_calls()
	assert result.check_status == CheckStatus.OK
	assert len(result.partial_results) == 0

	with sync_redis_client() as redis_client:
		methods = redis_client.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
		assert len(methods) == 0


def test_check_licenses(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	result = check_opsi_licenses()
	assert result.check_status == "ok"
	assert result.partial_results is not None


def test_check_opsi_config(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [True]]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_opsi_config()
	print(result)
	assert result.check_status == CheckStatus.OK
	assert result.message == "No issues found in the opsi configuration."
	assert len(result.partial_results) == 1
	partial_result = result.partial_results[0]
	assert partial_result.message == "Configuration opsiclientd.global.verify_server_cert is set to default."

	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [False]]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_opsi_config()
	assert result.check_status == CheckStatus.WARNING
	assert result.message == "1 issues found in the opsi configuration."
	assert len(result.partial_results) == 1
	partial_result = result.partial_results[0]
	assert partial_result.message == "Configuration opsiclientd.global.verify_server_cert is set to [False] - default is [True]."

	rpc = {"id": 1, "method": "config_delete", "params": ["opsiclientd.global.verify_server_cert"]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_opsi_config()
	assert result.check_status == CheckStatus.ERROR
	assert result.message == "1 issues found in the opsi configuration."
	assert len(result.partial_results) == 1
	partial_result = result.partial_results[0]
	assert partial_result.message == "Configuration opsiclientd.global.verify_server_cert does not exist."


def test_check_ldap_connection() -> None:
	result = check_ldap_connection()
	assert result.check_status == CheckStatus.OK
	assert result.message == "LDAP authentication is not configured."
	with get_opsi_config([{"category": "ldap_auth", "config": "ldap_url", "value": "ldaps://no-server"}]):
		result = check_ldap_connection()
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "Could not connect to LDAP Server."

	result = check_ldap_connection()
	assert result.check_status == CheckStatus.OK
	assert result.message == "LDAP authentication is not configured."
