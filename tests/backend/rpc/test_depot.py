# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd.backend.rpc.depot
"""

import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from opsicommon.objects import NetbootProduct
from opsisystem.inffile import Architecture, INFTargetOSVersion

from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401

TESTDIR = Path("tests/data/workbench/test_dir")
TESTFILE = TESTDIR / "testfile"
TESTPACKAGE_NAME = "localboot_legacy"
TESTPACKAGE = Path(f"tests/data/workbench/{TESTPACKAGE_NAME}_42.0-1337.opsi")
CONTROLFILE = Path("tests/data/workbench/control")


def test_depot_createDriverLinks(
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
	with patch("opsiconfd.backend.rpc.depot.DEPOT_DIR", str(tmp_path)), patch(
		"opsiconfd.backend.rpc.depot.get_target_os_versions", return_value=get_target_os_versions
	):
		backend.depot_createDriverLinks(productId=product.id)

	for sub_dir in ("x64/10.0.22000/PCI/1AF4", "x86/10.0.1507/PCI/1AF4"):
		for device_id in ("1001", "1003", "1042", "1043"):
			link = client_data_dir / "driver_db" / sub_dir / device_id
			assert link.is_symlink()
			inf_file = next(link.resolve().glob("*.inf"))
			assert inf_file.exists()
			assert inf_file.is_file()


def test_workbench_buildPackage(
	backend: UnprotectedBackend,  # noqa: F811
	tmp_path: Path,
) -> None:
	workbench_path = tmp_path / "workbench"
	with (
		patch("opsiconfd.backend.rpc.depot.WORKBENCH_DIR", str(workbench_path)),
	):
		package_dir = TESTDIR / "testpackage"
		Path(package_dir / "CLIENT_DATA").mkdir(parents=True, exist_ok=True)
		Path(package_dir / "CLIENT_DATA" / "test.file").write_bytes(b"opsi")
		Path(package_dir / "OPSI").mkdir(exist_ok=True)
		shutil.copy(CONTROLFILE, Path(package_dir / "OPSI"))
		shutil.copytree(package_dir, Path(workbench_path / "testpackage"))
		backend.workbench_buildPackage("testpackage")

		assert (workbench_path / "testpackage" / "localboot_new_42.0-1337.opsi").exists()


def test_workbench_buildPackage_symlink(
	backend: UnprotectedBackend,  # noqa: F811
	tmp_path: Path,
) -> None:
	data_dir = Path(tmp_path / "data")
	data_dir.mkdir(exist_ok=True)
	os.symlink(data_dir, tmp_path / "workbench")
	workbench_path = tmp_path / "workbench"

	with (
		patch("opsiconfd.backend.rpc.depot.WORKBENCH_DIR", str(workbench_path)),
	):
		package_dir = TESTDIR / "testpackage"
		Path(package_dir / "CLIENT_DATA").mkdir(parents=True, exist_ok=True)
		Path(package_dir / "CLIENT_DATA" / "test.file").write_bytes(b"opsi")
		Path(package_dir / "OPSI").mkdir(exist_ok=True)
		shutil.copy(CONTROLFILE, Path(package_dir / "OPSI"))
		shutil.copytree(package_dir, Path(workbench_path / "testpackage"))
		backend.workbench_buildPackage("testpackage")

		assert (workbench_path / "testpackage" / "localboot_new_42.0-1337.opsi").exists()


def test_workbench_buildPackage_Invalidpackagefile(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	with pytest.raises(ValueError):
		backend.workbench_buildPackage("/var/lib/opsi/workbench/test/../../../etc/opsi/")


def test_workbench_installPackage(
	backend: UnprotectedBackend,  # noqa: F811
	tmp_path: Path,
) -> None:
	workbench_path = tmp_path / "workbench"
	depot_path = tmp_path / "depot"
	with (
		patch("opsiconfd.backend.rpc.depot.WORKBENCH_DIR", str(workbench_path)),
		patch("opsiconfd.backend.rpc.depot.DEPOT_DIR", str(depot_path)),
	):
		package_dir = TESTDIR / "testpackage"
		Path(package_dir / "CLIENT_DATA").mkdir(parents=True, exist_ok=True)
		Path(package_dir / "CLIENT_DATA" / "test.file").write_bytes(b"opsi")
		Path(package_dir / "OPSI").mkdir(exist_ok=True)
		shutil.copy(CONTROLFILE, Path(package_dir / "OPSI"))
		shutil.copytree(package_dir, Path(workbench_path / "testpackage"))
		backend.workbench_buildPackage("testpackage")

		assert (workbench_path / "testpackage" / "localboot_new_42.0-1337.opsi").exists()

		backend.workbench_installPackage("testpackage")
		assert (depot_path / "localboot_new").exists()
