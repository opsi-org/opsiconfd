# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
diagnostic tests
"""
from pathlib import Path
from typing import Any
from unittest.mock import PropertyMock, patch

from opsiconfd.config import get_depotserver_id
from opsiconfd.diagnostic import (
	get_backendmanager_extension_methods,
	get_disk_info,
	get_lsb_release,
	get_memory_info,
	get_opsi_product_versions,
	get_os_release,
	get_processor_info,
	get_system_info,
)
from opsiconfd.diagnostic import get_config as config_info

from .backend.rpc.test_obj_product_on_depot import create_test_pods
from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	get_config,
	sync_clean_redis,
	test_client,
)


# LSB_RELASE_COMMAND = ["lsb_release", "-a"]
def test_os_release(tmp_path: Path) -> None:
	os_release_file = tmp_path / "os_release"
	os_release_file.write_text(
		'PRETTY_NAME="Debian GNU/Linux 10 (buster)"\n'
		'NAME="Debian GNU/Linux"\n'
		'VERSION_ID="10"\n'
		'VERSION="10 (buster)"\n'
		"VERSION_CODENAME=buster\n"
		"ID=debian\n"
		'HOME_URL="https://www.debian.org/"\n'
		'SUPPORT_URL="https://www.debian.org/support"\n'
		'BUG_REPORT_URL="https://bugs.debian.org/"\n',
		encoding="utf-8",
	)

	with patch("opsiconfd.diagnostic.OS_RELEASE_FILE", str(os_release_file)):
		data = get_os_release()
		assert data["ID"] == "debian"
		assert data["VERSION"] == "10 (buster)"
		assert data["BUG_REPORT_URL"] == "https://bugs.debian.org/"

		os_release_file.unlink()
		data = get_os_release()
		assert not data


def test_lsb_release() -> None:
	class Proc:
		stdout = (
			"No LSB modules are available.\n"
			"Distributor ID:	Debian\n"
			"Description:	Debian GNU/Linux 10 (buster)\n"
			"Release:	10\n"
			"Codename:	buster\n"
		)

	with patch("opsiconfd.diagnostic.LSB_RELASE_COMMAND", ["fail_command"]):
		data = get_lsb_release()
		assert not data

	with patch("opsiconfd.diagnostic.run", PropertyMock(return_value=Proc())):
		data = get_lsb_release()
		assert data["DISTRIBUTOR_ID"] == "Debian"
		assert data["DESCRIPTION"] == "Debian GNU/Linux 10 (buster)"
		assert data["RELEASE"] == "10"


def test_get_processor_info() -> None:
	read_text = """
		processor       : 0
		vendor_id       : GenuineIntel
		cpu family      : 6
		model           : 142
		model name      : Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
		stepping        : 12
		microcode       : 0xf0
		cpu MHz         : 2000.000
	"""

	with patch("opsiconfd.diagnostic.Path.read_text", return_value=read_text):
		data = get_processor_info()
		assert data["model"] == "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz"
		assert isinstance(data["cpu_count"], int)
		assert isinstance(data["load_avg"], tuple)
		assert len(data["load_avg"]) == 3


def test_get_memory_info() -> None:
	class MemoryInfo:
		total: int = 8589934592
		available: int = 4294967296
		percent: float = 50

	with patch("psutil.virtual_memory", PropertyMock(return_value=MemoryInfo())):
		data = get_memory_info()
		assert data["total"] == 8589934592
		assert data["available"] == 4294967296
		assert data["used_percent"] == 50
		assert data["total_human"] == "8.0GiB"
		assert data["available_human"] == "4.0GiB"


# @pytest.mark.skip(reason="check mockup")
def test_get_disk_info() -> None:
	class DiskInfo:
		total: int = 8589934592
		used: int = 4294967296
		free: int = 4294967296

	def get_disk_mountpoints() -> set:
		return {"/var/lib/opsi"}

	with patch("opsiconfd.diagnostic.get_disk_mountpoints", get_disk_mountpoints):
		with patch("psutil.disk_usage", PropertyMock(return_value=DiskInfo())):
			info = get_disk_info()
			data: dict[str, Any] = info.get("/var/lib/opsi")  # type: ignore
			assert data.get("total") == 8589934592
			assert data["used"] == 4294967296
			assert data["free"] == 4294967296
			assert data["total_human"] == "8.0GiB"
			assert data["used_human"] == "4.0GiB"
			assert data["free_human"] == "4.0GiB"


def test_get_system_info() -> None:
	class Hostnamectl:
		stdout = """
			Static hostname: test-t590
			Icon name: computer-laptop
			Chassis: laptop
			Machine ID: fooblabla
			Boot ID: blablafoo
			Operating System: Zorin OS 16.2
			Kernel: Linux 5.15.0-58-generic
			Architecture: x86-64
		"""

	def running_in_docker() -> bool:
		return False

	with (
		patch("opsiconfd.diagnostic.run", PropertyMock(return_value=Hostnamectl())),
		patch("opsiconfd.diagnostic.running_in_docker", running_in_docker),
	):
		data = get_system_info()
		assert data["Static hostname"] == "test-t590"
		assert data["Icon name"] == "computer-laptop"
		assert data["Chassis"] == "laptop"
		assert data["Machine ID"] == "fooblabla"
		assert data["Boot ID"] == "blablafoo"
		assert data["Operating System"] == "Zorin OS 16.2"
		assert data["Kernel"] == "Linux 5.15.0-58-generic"
		assert data["Architecture"] == "x86-64"
		assert not data["docker"]
		assert isinstance(data["product_name"], str)


def test_get_config() -> None:
	conf = config_info()
	for key in ["ssl_server_key_passphrase", "ssl_ca_key_passphrase"]:
		assert conf[key] == "********"


def test_get_backendmanager_extension_methods() -> None:
	method_info = get_backendmanager_extension_methods()

	assert isinstance(method_info["deleteServer"], dict)
	delete_server = method_info["deleteServer"]
	assert delete_server["signature"] == [{"self": "<class 'inspect._empty'>"}, {"serverId": "<class 'str'>"}]
	assert delete_server["file"] == "tests/data/opsi-config/backendManager/extend.d/45_deprecated.conf"
	assert delete_server["overwrite"]


def test_get_opsi_product_versions(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	create_test_pods(test_client)

	product_versions = get_opsi_product_versions()
	depot_id = get_depotserver_id()
	assert isinstance(product_versions[depot_id], dict)
	assert product_versions[depot_id]["test-backend-rpc-product-1"] == {"version": "5.3.0-2", "type": "LocalbootProduct"}
	assert product_versions[depot_id]["test-backend-rpc-product-2"] == {"version": "5.3.0-2", "type": "LocalbootProduct"}