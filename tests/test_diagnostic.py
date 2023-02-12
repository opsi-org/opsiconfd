# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
diagnostic tests
"""

from pathlib import Path
from unittest.mock import PropertyMock, patch

from opsiconfd.diagnostic import (
	get_disk_info,
	get_lsb_release,
	get_memory_info,
	get_os_release,
	get_processor_info,
)

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
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
	class Proc:  # pylint: disable=too-few-public-methods
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
	class CPUInfo:  # pylint: disable=too-few-public-methods
		stdout = """
			processor       : 0
			vendor_id       : GenuineIntel
			cpu family      : 6
			model           : 142
			model name      : Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
			stepping        : 12
			microcode       : 0xf0
			cpu MHz         : 2000.000
		"""

	with patch("opsiconfd.diagnostic.run", PropertyMock(return_value=CPUInfo())):
		data = get_processor_info()
		assert data["model"] == "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz"
		assert isinstance(data["cpu_count"], int)
		assert isinstance(data["load_avg"], tuple)
		assert len(data["load_avg"]) == 3


def test_get_memory_info() -> None:
	class MemoryInfo:  # pylint: disable=too-few-public-methods
		total: int = 8589934592
		available: int = 4294967296
		used_percent: float = 50

	with patch("opsiconfd.diagnostic.run", PropertyMock(return_value=MemoryInfo())):
		data = get_memory_info()
		assert data["total"] == 8589934592
		assert data["available"] == 4294967296
		assert data["used_percent"] == 50
		assert data["total_human"] == "8GB"
		assert data["available_human"] == "4GB"


def test_get_disk_info() -> None:
	class DiskInfo:  # pylint: disable=too-few-public-methods
		total: int = 8589934592
		used: int = 4294967296
		free: int = 4294967296

	with patch("opsiconfd.diagnostic.run", PropertyMock(return_value=DiskInfo())):
		data = get_disk_info()
		assert data["total"] == 8589934592
		assert data["used"] == 4294967296
		assert data["free"] == 4294967296
		assert data["total_human"] == "8GB"
		assert data["used_human"] == "4GB"
		assert data["free_human"] == "4GB"
