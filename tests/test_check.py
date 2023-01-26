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
from opsicommon.objects import (  # type: ignore[import]
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
	check_mysql,
	check_opsi_licenses,
	check_opsiconfd_config,
	check_product_on_clients,
	check_product_on_depots,
	check_redis,
	check_system_packages,
	get_repo_versions,
	health_check,
	process_check_result,
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
				assert partial_result.details == {"config": "log-level-stderr", "value": 9}
			elif partial_result.check_id == "opsiconfd_config:debug-options":
				assert partial_result.check_status == CheckStatus.ERROR
				assert partial_result.message == "The following debug options are set: rpc-log, asyncio."
				assert partial_result.details == {  # pylint: disable=loop-invariant-statement
					"config": "debug-options",  # pylint: disable=loop-invariant-statement
					"value": ["rpc-log", "asyncio"],  # pylint: disable=loop-invariant-statement
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
	with mock.patch("opsiconfd.utils.get_redis_connection", side_effect=RedisConnectionError("Redis test error")):
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
		"opsiconfd.check.get_mysql", side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")')
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
		mock.patch("opsiconfd.check.isOpenSUSE", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isSLES", mock.PropertyMock(return_value=False)),
	):

		result = check_system_packages()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in installed_versions.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK

		for partial_result in result.partial_results:
			assert partial_result.check_status == "ok"
			assert partial_result.message == (
				f"Package {partial_result.details['package']} is up to date. " f"Installed version: {partial_result.details['version']}"
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
		mock.patch("opsiconfd.check.isOpenSUSE", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isSLES", mock.PropertyMock(return_value=False)),
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

		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in installed_versions.items():
			assert f"Package {name} is out of date. Installed version: {version}" in captured_output


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
		mock.patch("opsiconfd.check.isOpenSUSE", mock.PropertyMock(return_value=True)),
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=False)),
		mock.patch("opsiconfd.check.isSLES", mock.PropertyMock(return_value=False)),
	):
		result = check_system_packages()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in repo_versions.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK
		for partial_result in result.partial_results:
			assert partial_result.check_status == CheckStatus.OK
			assert partial_result.message == (
				f"Package {partial_result.details['package']} is up to date. " f"Installed version: {partial_result.details['version']}"
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
		mock.patch("opsiconfd.check.isRHEL", mock.PropertyMock(return_value=True)),
	):
		result = check_system_packages()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		for name, version in repo_versions.items():
			assert f"Package {name} is up to date. Installed version: {version}" in captured_output

		assert result.message == "All packages are up to date."
		assert result.check_status == CheckStatus.OK

		for partial_result in result.partial_results:
			assert partial_result.check_status == CheckStatus.OK
			assert partial_result.message == (
				f"Package {partial_result.details['package']} is up to date. " f"Installed version: {partial_result.details['version']}"
			)


def _prepare_products(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)  # type: ignore
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
	assert len(results) == 10
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
	with catch_warnings():
		simplefilter("ignore")
		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)

	assert res.status_code == 200
	time.sleep(3)

	result = check_deprecated_calls()

	# print(result)
	assert result.check_status == CheckStatus.WARNING
	assert len(result.partial_results) == 1
	partial_result = result.partial_results[0]
	# print(partial_result)
	assert partial_result.details["method"] == DEPRECATED_METHOD
	assert partial_result.details["calls"] == "1"
	assert partial_result.details["last_call"]
	last_call_dt = datetime.fromisoformat(partial_result.details["last_call"].replace("Z", "")).astimezone(timezone.utc)
	assert (last_call_dt - current_dt).total_seconds() < 3
	assert isinstance(partial_result.details["applications"], list)
	assert partial_result.details["applications"] == ["testclient"]

	captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
	assert "Deprecated method 'getClientIds_list' was called" in captured_output


def test_check_licenses(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	result = check_opsi_licenses()
	assert result.check_status == "ok"
	assert result.partial_results is not None
