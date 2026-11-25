# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.depot
"""

import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401

TESTDIR = Path("tests/data/workbench/test_dir")
TESTFILE = TESTDIR / "testfile"
TESTPACKAGE_NAME = "localboot_legacy"
TESTPACKAGE = Path(f"tests/data/workbench/{TESTPACKAGE_NAME}_42.0-1337.opsi")
CONTROLFILE = Path("tests/data/workbench/control")


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


def test_depot_installPackage_boot_dir(
	backend: UnprotectedBackend,  # noqa: F811
	tmp_path: Path,
) -> None:
	workbench_path = tmp_path / "workbench"
	depot_path = tmp_path / "depot"
	boot_path = tmp_path / "boot"
	depot_path.mkdir()
	package_dir = workbench_path / "netboot_boot"
	(package_dir / "OPSI").mkdir(parents=True)
	(package_dir / "CLIENT_DATA").mkdir()
	(package_dir / "CLIENT_DATA" / "test.file").write_bytes(b"opsi")
	control = CONTROLFILE.read_text(encoding="utf-8").replace("type: localboot", "type: netboot").replace("localboot_new", "netboot_boot")
	(package_dir / "OPSI" / "control").write_text(control, encoding="utf-8")

	def build_and_install(kernel: bytes | None, client_data: bool = True) -> None:
		if not client_data:
			shutil.rmtree(package_dir / "CLIENT_DATA", ignore_errors=True)
		shutil.rmtree(package_dir / "BOOT", ignore_errors=True)
		if kernel is not None:
			(package_dir / "BOOT").mkdir()
			(package_dir / "BOOT" / "kernel.x64").write_bytes(kernel)
		backend.workbench_installPackage("netboot_boot")

	with (
		patch("opsiconfd.backend.rpc.depot.WORKBENCH_DIR", str(workbench_path)),
		patch("opsiconfd.backend.rpc.depot.DEPOT_DIR", str(depot_path)),
		patch("opsiconfd.backend.rpc.depot.PRODUCT_BOOT_DIR", str(boot_path)),
	):
		build_and_install(b"kernel-1")
		assert (boot_path / "netboot_boot" / "kernel.x64").read_bytes() == b"kernel-1"
		assert not (depot_path / "netboot_boot" / "kernel.x64").exists()
		assert not (depot_path / "netboot_boot" / "BOOT").exists()

		(boot_path / "netboot_boot" / "stale.file").write_bytes(b"stale")
		build_and_install(b"kernel-2")
		assert (boot_path / "netboot_boot" / "kernel.x64").read_bytes() == b"kernel-2"
		assert not (boot_path / "netboot_boot" / "stale.file").exists()
		assert sorted(p.name for p in boot_path.iterdir()) == ["netboot_boot"]

		build_and_install(None)
		assert (depot_path / "netboot_boot" / "test.file").exists()
		assert not (boot_path / "netboot_boot").exists()

		build_and_install(b"kernel-3")
		assert (boot_path / "netboot_boot" / "kernel.x64").read_bytes() == b"kernel-3"

		# Package with BOOT only
		build_and_install(b"kernel-4", client_data=False)
		assert (boot_path / "netboot_boot" / "kernel.x64").read_bytes() == b"kernel-4"
		assert (depot_path / "netboot_boot").is_dir()
		assert not any((depot_path / "netboot_boot").iterdir())

		backend.depot_uninstallPackage("netboot_boot")
		assert not (depot_path / "netboot_boot").exists()
		assert not (boot_path / "netboot_boot").exists()
