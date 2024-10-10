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

from opsicommon.objects import AuditHardwareOnHost, NetbootProduct, OpsiClient
from opsisystem.inffile import Architecture, INFTargetOSVersion

from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401

TESTDIR = Path("tests/data/workbench/test_dir")
TESTFILE = TESTDIR / "testfile"
TESTPACKAGE_NAME = "localboot_legacy"
TESTPACKAGE = Path(f"tests/data/workbench/{TESTPACKAGE_NAME}_42.0-1337.opsi")
CONTROLFILE = Path("tests/data/workbench/control")


def test_driver_updateDatabase_and_getSources(
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

		links = []
		for sub_dir in ("x64/10.0.22000/PCI/1AF4", "x86/10.0.1507/PCI/1AF4"):
			for device_id in ("1001", "1003", "1042", "1043"):
				links.append(client_data_dir / "driver_db" / sub_dir / device_id)

		for device_id in ("0236", "0289", "0295"):
			links.append(client_data_dir / "driver_db" / "x64/10.0.22000/HDAUDIO/10EC" / device_id)

		for device_id in ("4001", "4008", "400E", "4014", "4016", "402D", "402E", "4C63"):
			links.append(client_data_dir / "driver_db" / "x64/10.0.22000/USB/0BDA" / device_id)

		for link in links:
			assert link.is_symlink()
			inf_file = next(link.resolve().glob("*.inf"))
			assert inf_file.exists()
			assert inf_file.is_file()

		client = OpsiClient(id="test-client.opsi.test")
		ahohs = [
			AuditHardwareOnHost(
				hardwareClass="PCI_DEVICE",
				hostId=client.id,
				name="Red Hat VirtIO SCSI controller",
				vendor="Red Hat, Inc.",
				deviceType="PCI",
				vendorId="1AF4",
				deviceId="1001",
				subsystemVendorId="1AF4",
				subsystemDeviceId="0001",
				revision="00",
			),
			AuditHardwareOnHost(
				hardwareClass="USB_DEVICE",
				hostId=client.id,
				name="Realtek USB Audio",
				vendor="Realtek",
				vendorId="0BDA",
				deviceId="4001",
			),
			AuditHardwareOnHost(
				hardwareClass="HDAUDIO_DEVICE",
				hostId=client.id,
				name="Realtek Audio",
				vendor="Realtek",
				vendorId="10EC",
				deviceId="0236",
				subsystemVendorId="09E3",
				subsystemDeviceId="1028",
			),
		]

		backend.host_createObjects([client])
		backend.auditHardwareOnHost_createObjects(ahohs)

		sources = backend.driver_getSources(productId=product.id, architecture="x64", osVersion="10.0.22000", clientId=client.id)
		sources.sort(key=lambda src: src.url)
		assert len(sources) == 3

		for source in sources:
			assert source.binary_type == "windows_driver"
			assert source.access_type == "depot"
			assert source.operation_type == "recursive_copy"

		assert sources[0].url == "win11-x64-drivers-test/driver_db/x64/10.0.22000/HDAUDIO/10EC/0236"
		assert sources[0].information["device_type"] == "HDAUDIO"
		assert sources[0].information["vendor_id"] == "10EC"
		assert sources[0].information["device_id"] == "0236"
		assert sources[0].information["device_name"] == "Realtek Audio"

		assert sources[1].url == "win11-x64-drivers-test/driver_db/x64/10.0.22000/PCI/1AF4/1001"
		assert sources[1].information["device_type"] == "PCI"
		assert sources[1].information["vendor_id"] == "1AF4"
		assert sources[1].information["device_id"] == "1001"
		assert sources[1].information["vendor_name"] == "Red Hat, Inc."
		assert sources[1].information["device_name"] == "Red Hat VirtIO SCSI controller"

		assert sources[2].url == "win11-x64-drivers-test/driver_db/x64/10.0.22000/USB/0BDA/4001"
		assert sources[2].information["device_type"] == "USB"
		assert sources[2].information["vendor_id"] == "0BDA"
		assert sources[2].information["device_id"] == "4001"
		assert sources[2].information["vendor_name"] == "Realtek"
		assert sources[2].information["device_name"] == "Realtek USB Audio"

		sources = backend.driver_getSources(productId=product.id, architecture="x86", osVersion="10.0.1507", clientId=client.id)
		assert len(sources) == 1

		assert sources[0].binary_type == "windows_driver"
		assert sources[0].access_type == "depot"
		assert sources[0].operation_type == "recursive_copy"
		assert sources[0].url == "win11-x64-drivers-test/driver_db/x86/10.0.1507/PCI/1AF4/1001"
		assert sources[0].information["device_type"] == "PCI"
		assert sources[0].information["vendor_id"] == "1AF4"
		assert sources[0].information["device_id"] == "1001"
		assert sources[0].information["vendor_name"] == "Red Hat, Inc."
		assert sources[0].information["device_name"] == "Red Hat VirtIO SCSI controller"
