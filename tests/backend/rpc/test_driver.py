# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.depot
"""

import shutil
from pathlib import Path
from unittest.mock import patch

from opsicommon.logging import use_logging_config
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
	product_id = "win11-x64-drivers-test"
	client_id = "test-client.opsi.test"
	client_data_dir = tmp_path / product_id
	base_dir = client_data_dir / "drivers"
	drivers_dir = base_dir / "drivers"
	excluded_dir = drivers_dir / "excluded"
	additional_dir = drivers_dir / "additional"
	by_audit_dir = additional_dir / "byAudit"
	driver_db_dir = client_data_dir / "drivers" / "driver_db"
	legacy_pciids_dir = base_dir / "pciids"
	legacy_usbids_dir = base_dir / "usbids"
	legacy_hdaudioids_dir = base_dir / "hdaudioids"

	client_data_dir.mkdir()
	shutil.copytree("tests/data/windows_drivers", drivers_dir)
	excluded_dir.mkdir()
	additional_dir.mkdir()
	shutil.move(drivers_dir / "vioserial", excluded_dir / "vioserial")

	by_audit_inf1 = by_audit_dir / "A Vendor." / "Some model_" / "sub1" / "driver1.inf"
	by_audit_inf2 = by_audit_dir / "A Vendor." / "Some model_" / "sub2" / "driver2.inf"
	by_audit_inf3 = by_audit_dir / "A Vendor." / "Some model_" / "sub3" / "sub3" / "driver3.inf"

	additional_drv1 = additional_dir / "additional1" / "sub1" / "driver1.inf"
	additional_drv2 = additional_dir / "additional2" / "sub2" / "sub2" / "driver2.inf"
	additional_drv3 = additional_dir / "additional3" / "sub3" / "driver3.inf"
	additional_drv4 = additional_dir / "additional3" / "sub33" / "driver33.inf"
	additional_drv5 = additional_dir / "additional4" / "driver4.inf"

	by_audit_inf1.parent.mkdir(parents=True)
	by_audit_inf1.touch()
	by_audit_inf2.parent.mkdir(parents=True)
	by_audit_inf2.touch()
	by_audit_inf3.parent.mkdir(parents=True)
	by_audit_inf3.touch()

	additional_drv1.parent.mkdir(parents=True)
	additional_drv1.touch()
	additional_drv2.parent.mkdir(parents=True)
	additional_drv2.touch()
	additional_drv3.parent.mkdir(parents=True)
	additional_drv3.touch()
	additional_drv4.parent.mkdir(parents=True)
	additional_drv4.touch()
	additional_drv5.parent.mkdir(parents=True)
	additional_drv5.touch()

	get_target_os_versions = [
		INFTargetOSVersion(Architecture=Architecture.X64, OSMajorVersion=10, OSMinorVersion=0, BuildNumber=22000),
		INFTargetOSVersion(Architecture=Architecture.X86, OSMajorVersion=10, OSMinorVersion=0, BuildNumber=1507),
	]

	product = NetbootProduct(id=product_id, productVersion="1", packageVersion="1")
	backend.product_createObjects([product])

	with (
		use_logging_config(stderr_level=5),
		patch("opsiconfd.backend.rpc.driver.DEPOT_DIR", str(tmp_path)),
		patch("opsiconfd.backend.rpc.driver.get_target_os_versions", return_value=get_target_os_versions),
		patch("opsiconfd.backend.rpc.driver.find_wim_files", return_value=[Path("install.wim")]),
		patch.object(
			backend,
			"productPropertyState_getValues",
			lambda **kwargs: {
				client_id: {
					product_id: {
						"image": ["install.wim:0"],
						"additional_drivers": ["additional2", "additional3", "additional_missing"],
					}
				}
			},
		),
	):
		install_wim = tmp_path / product_id / "images" / "install.wim"
		install_wim.parent.mkdir(parents=True)
		install_wim.touch()
		backend.driver_updateDatabase(productId=product.id)

		links: list[Path] = []
		missing_links: list[Path] = []

		# PCI
		for device_id in ("1001", "1042"):
			# driver_db
			for sub_dir in ("x64/10.0.22000/PCI/1AF4", "x86/10.0.1507/PCI/1AF4"):
				links.append(driver_db_dir / sub_dir / device_id)
			# Legacy
			links.append(legacy_pciids_dir / "1AF4" / device_id)

		# PCI excluded
		for device_id in ("1003", "1043"):
			# driver_db
			missing_links.append(driver_db_dir / sub_dir / device_id)
			# Legacy
			missing_links.append(legacy_pciids_dir / "1AF4" / device_id)

		# HDAUDIO
		for device_id in ("0236", "0289", "0295"):
			# driver_db
			links.append(driver_db_dir / "x64/10.0.22000/HDAUDIO/10EC" / device_id)
			# Legacy
			links.append(legacy_hdaudioids_dir / "10EC" / device_id)

		# USB
		for device_id in ("4001", "4008", "400E", "4014", "4016", "402D", "402E", "4C63"):
			# driver_db
			links.append(driver_db_dir / "x64/10.0.22000/USB/0BDA" / device_id)
			# Legacy
			links.append(legacy_usbids_dir / "0BDA" / device_id)

		for link in links:
			assert link.is_symlink()
			inf_file = next(link.resolve().glob("*.inf"))
			assert inf_file.exists()
			assert inf_file.is_file()

		for link in missing_links:
			assert not link.exists()

		client = OpsiClient(id=client_id)
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
			AuditHardwareOnHost(
				hardwareClass="COMPUTER_SYSTEM",
				hostId=client.id,
				vendor="A VENDOR_",
				model="some model (some sku).",
				description="",
				totalPhysicalMemory=8589389824,
				name="COMPUTERNAME",
				systemType="x64-based PC",
				sku="some sku",
				systemUUID="25aa985c-9f87-462e-b005-eea8fdae9546",
			),
			AuditHardwareOnHost(
				hardwareClass="BASE_BOARD",
				hostId=client.id,
				vendor="Other Vendor",
				model="Other model",
			),
		]

		backend.host_createObjects([client])
		backend.auditHardwareOnHost_createObjects(ahohs)

		for architecture, os_version in (("x64", "10.0.22000"), ("x64", None), (None, "10.0.22000"), (None, None)):
			# Default image: x64 10.0.22000
			sources = backend.driver_getSources(productId=product.id, clientId=client.id, architecture=architecture, osVersion=os_version)
			sources.sort(key=lambda src: src.url)

			assert len(sources) == 9

			for source in sources:
				assert source.binary_type == "windows_driver"
				assert source.access_type == "depot"
				assert source.operation_type == "recursive_copy"

			assert sources[0].url == "win11-x64-drivers-test/drivers/driver_db/x64/10.0.22000/HDAUDIO/10EC/0236"
			assert sources[0].information["device_type"] == "HDAUDIO"
			assert sources[0].information["vendor_id"] == "10EC"
			assert sources[0].information["device_id"] == "0236"
			assert sources[0].information["device_name"] == "Realtek Audio"

			assert sources[1].url == "win11-x64-drivers-test/drivers/driver_db/x64/10.0.22000/PCI/1AF4/1001"
			assert sources[1].information["device_type"] == "PCI"
			assert sources[1].information["vendor_id"] == "1AF4"
			assert sources[1].information["device_id"] == "1001"
			assert sources[1].information["vendor_name"] == "Red Hat, Inc."
			assert sources[1].information["device_name"] == "Red Hat VirtIO SCSI controller"

			assert sources[2].url == "win11-x64-drivers-test/drivers/driver_db/x64/10.0.22000/USB/0BDA/4001"
			assert sources[2].information["device_type"] == "USB"
			assert sources[2].information["vendor_id"] == "0BDA"
			assert sources[2].information["device_id"] == "4001"
			assert sources[2].information["vendor_name"] == "Realtek"
			assert sources[2].information["device_name"] == "Realtek USB Audio"

			assert sources[3].url == "win11-x64-drivers-test/drivers/drivers/additional/additional2/sub2/sub2"
			assert sources[3].information["additional_dir"] == "additional2"

			assert sources[4].url == "win11-x64-drivers-test/drivers/drivers/additional/additional3/sub3"
			assert sources[4].information["additional_dir"] == "additional3"

			assert sources[5].url == "win11-x64-drivers-test/drivers/drivers/additional/additional3/sub33"
			assert sources[5].information["additional_dir"] == "additional3"

			assert sources[6].url == "win11-x64-drivers-test/drivers/drivers/additional/byAudit/A Vendor./Some model_/sub1"
			assert sources[7].url == "win11-x64-drivers-test/drivers/drivers/additional/byAudit/A Vendor./Some model_/sub2"
			assert sources[8].url == "win11-x64-drivers-test/drivers/drivers/additional/byAudit/A Vendor./Some model_/sub3/sub3"

			for source in sources[6:]:
				assert source.information["sys_vendor"] == "A VENDOR"
				assert source.information["sys_model"] == "some model (some sku)"
				assert source.information["board_vendor"] == "Other Vendor"
				assert source.information["board_model"] == "Other model"
				assert source.information["by_audit_vendor_dir_name"] == "A Vendor."
				assert source.information["by_audit_model_dir_name"] == "Some model_"

		sources = backend.driver_getSources(clientId=client.id, productId=product.id, architecture="x86", osVersion="10.0.1507")
		assert len(sources) == 7

		assert sources[0].binary_type == "windows_driver"
		assert sources[0].access_type == "depot"
		assert sources[0].operation_type == "recursive_copy"
		assert sources[0].url == "win11-x64-drivers-test/drivers/driver_db/x86/10.0.1507/PCI/1AF4/1001"
		assert sources[0].information["device_type"] == "PCI"
		assert sources[0].information["vendor_id"] == "1AF4"
		assert sources[0].information["device_id"] == "1001"
		assert sources[0].information["vendor_name"] == "Red Hat, Inc."
		assert sources[0].information["device_name"] == "Red Hat VirtIO SCSI controller"
