# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd.backend.rpc.depot
"""

import shutil
from pathlib import Path
from unittest.mock import patch

from opsicommon.objects import NetbootProduct
from opsisystem.inffile import Architecture, INFTargetOSVersion

from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401

TESTDIR = Path("tests/data/workbench/test_dir")
TESTFILE = TESTDIR / "testfile"
TESTPACKAGE_NAME = "localboot_legacy"
TESTPACKAGE = Path(f"tests/data/workbench/{TESTPACKAGE_NAME}_42.0-1337.opsi")
CONTROLFILE = Path("tests/data/workbench/control")


def test_driver_updateDatabase(
	backend: UnprotectedBackend,  # noqa: F811
	tmp_path: Path,
) -> None:
	product = NetbootProduct(id="win11-x64-drivers-test", productVersion="1", packageVersion="1")
	backend.product_createObjects([product])
	client_data_dir = tmp_path / product.id
	drivers_dir = client_data_dir / "drivers"
	client_data_dir.mkdir()
	shutil.copytree("tests/data/windows_drivers", drivers_dir)
	get_target_os_versions = [
		INFTargetOSVersion(Architecture=Architecture.X64, OSMajorVersion=10, OSMinorVersion=0, BuildNumber=22000),
		INFTargetOSVersion(Architecture=Architecture.X86, OSMajorVersion=10, OSMinorVersion=0, BuildNumber=1507),
	]
	with patch("opsiconfd.backend.rpc.driver.DEPOT_DIR", str(tmp_path)), patch(
		"opsiconfd.backend.rpc.driver.get_target_os_versions", return_value=get_target_os_versions
	):
		backend.driver_updateDatabase(productId=product.id)

	for sub_dir in ("x64/10.0.22000/PCI/1AF4", "x86/10.0.1507/PCI/1AF4"):
		for device_id in ("1001", "1003", "1042", "1043"):
			link = client_data_dir / "driver_db" / sub_dir / device_id
			assert link.is_symlink()
			inf_file = next(link.resolve().glob("*.inf"))
			assert inf_file.exists()
			assert inf_file.is_file()
