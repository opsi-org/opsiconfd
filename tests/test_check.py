# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
check tests
"""


import io
import os
import pprint
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from unittest import mock
from warnings import catch_warnings, simplefilter

import requests
from _pytest.fixtures import FixtureFunction
from mock import Mock  # type: ignore[import]
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

from opsiconfd.addon.manager import AddonManager
from opsiconfd.check.addon import check_opsi_failed_addons
from opsiconfd.check.cli import process_check_result
from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult
from opsiconfd.check.main import (
	check_depotservers,
	check_deprecated_calls,
	check_disk_usage,
	check_ldap_connection,
	check_mysql,
	check_opsi_config,
	check_opsi_licenses,
	check_opsi_users,
	check_opsiconfd_config,
	check_product_on_clients,
	check_product_on_depots,
	check_redis,
	check_run_as_user,
	check_ssl,
	check_system_packages,
	health_check,
)
from opsiconfd.check.opsipackages import get_available_product_versions
from opsiconfd.check.system import CHECK_SYSTEM_PACKAGES, check_system_repos, get_repo_versions
from opsiconfd.config import OPSICONFD_HOME, config, opsi_config
from opsiconfd.redis import redis_client
from opsiconfd.ssl import (
	create_ca,
	create_local_server_cert,
	get_ca_subject,
	store_ca_cert,
	store_ca_key,
	store_local_server_cert,
	store_local_server_key,
)
from opsiconfd.utils import NameService, UserInfo

from .test_addon_manager import cleanup  # noqa: F401
from .utils import (  # noqa: F401
	ACL_CONF_41,
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	clean_mysql,
	get_config,
	get_opsi_config,
	sync_clean_redis,
	test_client,
)
from .utils import (
	config as test_config,  # noqa: F401
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
	class MockUser:
		pw_name = "opsiconfd"
		pw_gid = 103
		pw_dir = OPSICONFD_HOME

	class MockGroup:
		gr_name = "nogroup"
		gr_gid = 65534

	mock_user = MockUser()

	def mock_getgrnam(groupname: str) -> MockGroup:
		group = MockGroup()
		group.gr_name = groupname
		if groupname == "shadow":
			group.gr_gid = 101
		elif groupname == opsi_config.get("groups", "admingroup"):
			group.gr_gid = 102
		elif groupname == opsi_config.get("groups", "fileadmingroup"):
			group.gr_gid = 103
		return group

	with mock.patch("opsiconfd.check.config.os.getgrouplist", mock.PropertyMock(return_value=(101, 102, 103))):
		with mock.patch("opsiconfd.check.config.pwd.getpwnam", mock.PropertyMock(return_value=mock_user)), mock.patch(
			"opsiconfd.check.config.grp.getgrnam", mock_getgrnam
		):
			result = check_run_as_user()

			pprint.pprint(result)
			assert result.check_status == CheckStatus.OK

		with mock.patch("opsiconfd.check.config.pwd.getpwnam", mock.PropertyMock(return_value=mock_user)), mock.patch(
			"opsiconfd.check.config.grp.getgrnam", mock_getgrnam
		):
			mock_user.pw_dir = "/wrong/home"
			result = check_run_as_user()
			assert result.check_status == CheckStatus.WARNING
			assert result.partial_results[0].details["home_directory"] == "/wrong/home"

	with (
		mock.patch("opsiconfd.check.config.os.getgrouplist", mock.PropertyMock(return_value=(1, 2, 3))),
		mock.patch("opsiconfd.check.config.pwd.getpwnam", mock.PropertyMock(return_value=mock_user)),
		mock.patch("opsiconfd.check.config.grp.getgrnam", mock_getgrnam),
	):
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


def test_check_opsiconfd_config(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text(ACL_CONF_41, encoding="utf-8")
	with get_config({"log_level_stderr": 9, "debug_options": ["rpc-log", "asyncio"], "acl_file": str(acl_file)}):
		result = check_opsiconfd_config()
		# print(result)
		ids_found = 0
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "3 issues found in the configuration."
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
			elif partial_result.check_id == "opsiconfd_config:acl-self-for-all":
				ids_found += 1
				assert partial_result.check_status == CheckStatus.ERROR
				assert partial_result.message == "'self' is allowed for '.*'."
		assert ids_found == 3


def test_check_depotservers(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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
	assert "No Redis issues found." in captured_output
	assert "Connection to Redis is working." in captured_output
	assert "RedisTimeSeries version " in captured_output
	assert "Redis memory usage is OK" in captured_output
	assert result.check_status == "ok"


def test_check_redis_error() -> None:
	console = Console(log_time=False, force_terminal=False, width=1000)

	with mock.patch("opsiconfd.redis.get_redis_connection", side_effect=RedisConnectionError("Redis test error")):
		result = check_redis()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		assert "Cannot connect to Redis" in captured_output
		assert result.check_status == "error"
		assert result.message == "Cannot connect to Redis: Redis test error"

	with mock.patch("opsiconfd.check.redis.MEMORY_USAGE_WARN", 1):
		result = check_redis()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
		assert "WARNING - Redis memory usage is high" in captured_output

	with mock.patch("opsiconfd.check.redis.MEMORY_USAGE_ERR", 1):
		result = check_redis()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
		assert "ERROR - Redis memory usage is too high" in captured_output


def test_check_mysql() -> None:
	console = Console(log_time=False, force_terminal=False, width=1000)
	with mock.patch("opsiconfd.check.mysql.MAX_ALLOWED_PACKET", 1):
		result = check_mysql()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		assert "No MySQL issues found." in captured_output
		assert result.check_status == "ok"
		assert result.message == "No MySQL issues found."


def test_check_mysql_error() -> None:
	with mock.patch(
		"opsiconfd.check.mysql.MySQLConnection.connect",
		side_effect=OperationalError('(MySQLdb.OperationalError) (2005, "Unknown MySQL server host bla (-3)")'),
	):
		console = Console(log_time=False, force_terminal=False, width=1000)
		result = check_mysql()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)

		assert '2005 - "Unknown MySQL server host bla (-3)"' in captured_output
		assert result.check_status == "error"
		assert result.message == '2005 - "Unknown MySQL server host bla (-3)"'

	with mock.patch("opsiconfd.check.mysql.MAX_ALLOWED_PACKET", 1_000_000_000):
		result = check_mysql()
		captured_output = captured_function_output(process_check_result, result=result, console=console, detailed=True)
		assert "is too small (should be at least 1000000000)" in captured_output


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
		mock.patch("opsiconfd.check.system.get_repo_versions", mock.PropertyMock(return_value=repo_versions)),
		mock.patch("opsiconfd.check.system.run", mock.PropertyMock(return_value=Proc())),
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


def _prepare_products(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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


def test_check_product_on_depots(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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


def test_check_product_on_clients(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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
	assert len(results) == 18
	for result in results:
		print(result.check_id, result.check_status)
		assert result.check_status


def test_check_deprecated_calls(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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
	redis = redis_client()
	methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
	assert len(methods) == 1
	redis.expire(f"{redis_prefix_stats}:rpcs:deprecated:{DEPRECATED_METHOD}:count", 1)
	time.sleep(5)
	result = check_deprecated_calls()
	assert result.check_status == CheckStatus.OK
	assert len(result.partial_results) == 0

	methods = redis.smembers(f"{redis_prefix_stats}:rpcs:deprecated:methods")
	assert len(methods) == 0


def test_check_licenses(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	result = check_opsi_licenses()
	assert result.check_status == "ok"
	assert result.partial_results is not None


def test_check_opsi_config(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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


def test_check_ssl(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	ssl_server_cert = tmpdir / "opsi-server-cert.pem"
	ssl_server_key = tmpdir / "opsi-server-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
		}
	):
		# CA key, CA cert, server key, server cert file missing
		result = check_ssl()
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "Some SSL issues where found."
		assert result.partial_results[0].message.startswith("A problem was found with the opsi CA certificate")
		assert result.partial_results[2].message.startswith("A problem was found with the opsi CA key")
		assert result.partial_results[3].message.startswith("A problem was found with the server certificate")
		assert result.partial_results[4].message.startswith("A problem was found with the server key")

		ca_subject = get_ca_subject()

		(ca_crt, ca_key) = create_ca(subject=ca_subject, valid_days=config.ssl_ca_cert_valid_days + 10)
		store_ca_key(ca_key)
		store_ca_cert(ca_crt)

		(srv_crt, srv_key) = create_local_server_cert(renew=False)
		store_local_server_cert(srv_crt)
		store_local_server_key(srv_key)

		result = check_ssl()
		assert result.check_status == CheckStatus.OK
		assert result.message == "No SSL issues found."
		assert (
			result.partial_results[0].message
			== f"The opsi CA certificate is OK and will expire in {config.ssl_ca_cert_valid_days + 9} days."
		)
		assert result.partial_results[1].check_status == CheckStatus.OK
		assert result.partial_results[1].message == "The opsi CA is not a intermediate CA."
		assert result.partial_results[2].message == "The opsi CA key is OK."

		with mock.patch(
			"opsiconfd.check.ssl.get_ca_subject",
			lambda: {
				"C": "DE",
				"ST": "RP",
				"L": "MAINZ",
				"O": "uib",
				"OU": "opsi@new.domain",
				"CN": config.ssl_ca_subject_cn,
				"emailAddress": "opsi@new.domain",
			},
		):
			result = check_ssl()
			assert result.check_status == CheckStatus.WARNING
			assert result.partial_results[0].message.startswith("The subject of the CA has changed from")

		(ca_crt, ca_key) = create_ca(subject=ca_subject, valid_days=config.ssl_ca_cert_renew_days - 10)
		store_ca_key(ca_key)
		store_ca_cert(ca_crt)
		result = check_ssl()

		assert result.check_status == CheckStatus.ERROR
		assert (
			result.partial_results[0].message
			== f"The opsi CA certificate is OK but will expire in {config.ssl_ca_cert_renew_days - 11} days."
		)
		assert result.partial_results[4].check_status == CheckStatus.ERROR
		assert result.partial_results[4].message == "Failed to verify server cert with opsi CA."


def test_checks_and_skip_checks() -> None:
	with get_config({"checks": ["redis", "mysql", "ssl"]}):
		list_of_checks = list(health_check())
		assert len(list_of_checks) == 3

	with get_config({"skip_checks": ["redis", "mysql", "ssl"]}):
		list_of_checks = list(health_check())
		assert len(list_of_checks) == 15


def test_check_opsi_users() -> None:
	result = check_opsi_users()
	assert result.check_status == CheckStatus.OK

	# If the server is part of a domain and the opsi users are local users, a warning should be issued.
	with (
		mock.patch(
			"opsiconfd.check.users.get_user_passwd_details",
			return_value=(
				[
					UserInfo(
						username="pcpatch",
						uid=1000,
						gid=1000,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService(NameService.FILES),
					)
				]
			),
		),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.FILES, NameService.SSS])),
	):
		result = check_opsi_users()
		assert result.check_status == CheckStatus.WARNING

	# If the server  is part of a domain and the opsi users are only domain users, no warning should be issued.
	with (
		mock.patch(
			"opsiconfd.check.users.get_user_passwd_details",
			return_value=(
				[
					UserInfo(
						username="pcpatch",
						uid=1000,
						gid=1000,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService.WINBIND,
					)
				]
			),
		),
		mock.patch(
			"opsiconfd.check.users.get_passwd_services", return_value=([NameService.FILES, NameService.SYSTEMD, NameService.WINBIND])
		),
	):
		result = check_opsi_users()
		assert result.check_status == CheckStatus.OK

	# If the server is part of a domain and the opsi users are local and domain users, an error should be issued.
	with (
		mock.patch(
			"opsiconfd.check.users.get_user_passwd_details",
			return_value=(
				[
					UserInfo(
						username="pcpatch",
						uid=1000,
						gid=1000,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService.LDAP,
					),
					UserInfo(
						username="pcpatch",
						uid=111111,
						gid=111111,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService.COMPAT,
					),
				]
			),
		),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.COMPAT, NameService.SYSTEMD, NameService.LDAP])),
	):
		result = check_opsi_users()
		assert result.check_status == CheckStatus.ERROR

	# If the server is not part of a domain and the opsi users are local users, no warning should be issued.
	with (
		mock.patch(
			"opsiconfd.check.users.get_user_passwd_details",
			return_value=(
				[
					UserInfo(
						username="pcpatch",
						uid=1000,
						gid=1000,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService.COMPAT,
					)
				]
			),
		),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.COMPAT, NameService.SYSTEMD])),
	):
		result = check_opsi_users()
		assert result.check_status == CheckStatus.OK

	# check for missing user
	with get_opsi_config([{"category": "depot_user", "config": "username", "value": "pcpatch-local"}]):
		result = check_opsi_users()
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "A required user does not exist."


def test_check_system_repos() -> None:
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
				result = check_system_repos()
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
			result = check_system_repos()
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
				result = check_system_repos()
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
				result = check_system_repos()
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
				result = check_system_repos()
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
				result = check_system_repos()
				assert result.check_status == CheckStatus.OK
				assert result.message == "No issues found with the system repositories."


def test_check_opsi_failed_addons(test_config: Config, cleanup: FixtureFunction) -> None:  # noqa: F811
	test_config.addon_dirs = [os.path.abspath("tests/data/addons")]

	addon_manager = AddonManager()
	addon_manager.load_addons()

	result = check_opsi_failed_addons()
	assert result.check_status == CheckStatus.ERROR

	test_config.addon_dirs = []

	addon_manager = AddonManager()
	addon_manager.load_addons()

	result = check_opsi_failed_addons()
	assert result.check_status == CheckStatus.OK


def test_check_opsi_config_checkmk(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [True]]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_opsi_config()
	checkmk = result.to_checkmk()
	assert checkmk.startswith("0")
	assert result.check_name in checkmk
	assert "No issues found in the opsi configuration." in checkmk
	assert "Configuration opsiclientd.global.verify_server_cert is set to default." in checkmk

	rpc = {"id": 1, "method": "config_createBool", "params": ["opsiclientd.global.verify_server_cert", "", [False]]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_opsi_config()
	checkmk = result.to_checkmk()
	assert checkmk.startswith("1")
	assert "1 issues found in the opsi configuration." in checkmk
	assert "Configuration opsiclientd.global.verify_server_cert is set to [False] - default is [True]." in checkmk

	rpc = {"id": 1, "method": "config_delete", "params": ["opsiclientd.global.verify_server_cert"]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	assert res.status_code == 200

	result = check_opsi_config()
	checkmk = result.to_checkmk()
	assert checkmk.startswith("2")
	assert "1 issues found in the opsi configuration." in checkmk
	assert "Configuration opsiclientd.global.verify_server_cert does not exist." in checkmk
