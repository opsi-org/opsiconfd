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
