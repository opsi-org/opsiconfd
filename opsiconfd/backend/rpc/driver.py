# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.driver

Base structure of the traditional drivers directory in a Windows netboot product:

CLIENT_DATA
├── drivers
│   ├── drivers
│   ├── additional
│   │   ├── byAudit
│   │   │   ├── <vendor-a>
│   │   │   │   ├── <model-c>
│   │   │   │   └── <model-d>
│   │   │   └── <vendor-b>
│   │   │       └── <model-e>
│   │   ├── <additional-name-1>
│   │   └── <additional-name-2>
│   ├── excluded
│   └── preferred
├── pci.ids
├── usb.ids
├── pciids
│   └── <vendor-id>
│       └── <device-id> (symlink)
├── usbids
│   └── <vendor-id>
│       └── <device-id> (symlink)
├── hdaudioids
│   └── <vendor-id>
│       └── <device-id> (symlink)
├── classes
│   └── <device-class>
│       └── <vendor-name>
│           └── <device-name> (symlink)
└── vendors
    └── <vendor-id>
        └── <device-id> (symlink)

Symlinks to driver directories under drivers/drivers are created in the
`pciids`, `usbids`, `hdaudioids`, `classes`, and `vendors` directories,
using information extracted from INF files in the drivers directory.
Drivers in `preferred` are given priority, while drivers in `excluded` are omitted from this process.
The `classes` and `vendors` directories serve informational purposes only.
Automatic driver integration is performed using the `pciids`, `usbids`, and `hdaudioids` directories.
The `byAudit` directory contains drivers added manually, based on system vendor and model information from hardware inventory.
This directory requires manual maintenance.
The `additional` directory contains subdirectories with custom names, which can be specified
in the product property `additional_drivers` to manually select extra drivers for a device.

Because the original automatic driver integration did not consider architecture or Windows version,
an alternative approach was introduced.

CLIENT_DATA
├── drivers
│   ├── drivers
│   ├── additional
│   │   ├── byAudit
│   │   │   ├── <vendor-a>
│   │   │   │   ├── <model-c>
│   │   │   │   └── <model-d>
│   │   │   └── <vendor-b>
│   │   │       └── <model-e>
│   │   ├── <additional-name-1>
│   │   └── <additional-name-2>
│   ├── excluded
│   └── preferred
├── pci.ids
├── usb.ids
└── driver_db
    └── <architecture>
        └── <windows-version>
            └── <device-type>
                └── <vendor-id>
                    └── <device-id> (symlink)

The `driver_db` directory contains symlinks to driver directories under `drivers/drivers`,
organized by architecture (x86 / x64 / arm64), Windows version (<major>.<minor>.<build>),
and device type (PCI / USB / HDAUDIO / ACPI).
"""

from __future__ import annotations

import re
import shutil
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import BackendError, BackendMissingDataError
from opsicommon.package.wim import wim_info
from opsicommon.types import forceHostId as typeForceHostId
from opsicommon.types import forceProductId as typeForceProductId
from opsisystem.inffile import Architecture, DeviceType, INFFile, INFTargetOSVersion

from opsiconfd.config import DEPOT_DIR
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class BinarySourceBinaryType(StrEnum):
	WINDOWS_DRIVER = "windows_driver"


class BinarySourceAccessType(StrEnum):
	DEPOT = "depot"


class BinarySourceOperationType(StrEnum):
	RECURSIVE_COPY = "recursive_copy"


@dataclass(kw_only=True, slots=True)
class BinarySource:
	binary_type: BinarySourceBinaryType
	access_type: BinarySourceAccessType
	operation_type: BinarySourceOperationType
	url: str
	information: dict[str, Any] = field(default_factory=dict)

	def as_dict(self) -> dict[str, Any]:
		"""
		Convert the BinarySource to a dictionary.
		"""
		return asdict(self)


def find_wim_files(client_data_dir: Path) -> list[Path]:
	wim_files = set()
	for image_dir in ("images", "installfiles/sources"):
		image_path = client_data_dir / image_dir
		if not image_path.exists():
			continue
		for file in image_path.iterdir():
			if file.is_symlink() and not file.exists():
				continue
			if file.suffix.lower() not in (".wim", ".esd", ".swm"):
				continue
			if file.suffix.lower() == ".swm" and re.match(r"\d+\.swm", file.stem):
				# Only process first part of split wim
				continue
			logger.info("Found WIM file '%s'", file)
			wim_files.add(file)
	return list(wim_files)


def get_target_os_versions(wim_image: Path, image_name_or_index: int | str | None = None) -> list[INFTargetOSVersion]:
	target_os_versions: list[INFTargetOSVersion] = []
	image_index = -1
	image_name = image_name_or_index
	try:
		image_index = int(image_name)  # type: ignore[arg-type]
		image_name = ""
	except (ValueError, TypeError):
		pass

	for image in wim_info(wim_image).images:
		logger.debug("Processing image %s in '%s'", image.name, wim_image)
		if not image.windows_info or (image_index > -1 and image.index != image_index) or (image_name and image.name != image_name):
			continue
		tov = INFTargetOSVersion(
			Architecture=Architecture.from_string(image.windows_info.architecture),
			OSMajorVersion=image.windows_info.major_version,
			OSMinorVersion=image.windows_info.minor_version,
			BuildNumber=image.windows_info.build,
		)
		logger.debug("Found target OS version %s", tov)
		target_os_versions.append(tov)

	return target_os_versions


class RPCDriverMixin(Protocol):
	@rpc_method
	def driver_updateDatabase(self: BackendProtocol, productId: str) -> None:
		"""
		Creation of the driver integration structure in the product's depot directory.
		"""
		product_id = typeForceProductId(productId)
		client_data_dir = Path(DEPOT_DIR) / product_id
		wim_files = find_wim_files(client_data_dir)
		if not wim_files:
			raise BackendError(f"No WIM files found in '{client_data_dir}'")

		target_os_versions = []
		for file in wim_files:
			for tov in get_target_os_versions(file):
				if tov not in target_os_versions:
					target_os_versions.append(tov)
		if not target_os_versions:
			raise BackendError(f"No target OS versions found in images for product '{product_id}'")

		base_dir = client_data_dir / "drivers"
		drivers_dir = base_dir / "drivers"
		driver_db_dir = base_dir / "driver_db"
		legacy_pciids_dir = base_dir / "pciids"
		legacy_usbids_dir = base_dir / "usbids"
		legacy_hdaudioids_dir = base_dir / "hdaudioids"
		for _dir in (driver_db_dir, legacy_pciids_dir, legacy_usbids_dir, legacy_hdaudioids_dir):
			if _dir.exists():
				shutil.rmtree(_dir)
			_dir.mkdir(parents=True)

		for file_path in drivers_dir.glob("**/*.[Ii][Nn][Ff]"):
			root_path = file_path.parent
			if root_path.relative_to(drivers_dir).parts[0] in ("additional", "excluded"):
				continue
			logger.info("Processing file '%s'", file_path)
			inf_file = INFFile(file_path)
			for tov in target_os_versions:
				logger.debug("Creating driver links for %s", tov)
				for dev in inf_file.get_devices(target_os_version=tov):
					logger.debug("Processing Hardware ID '%s'", dev.hardware_id)
					tov_dir = driver_db_dir / tov.Architecture / f"{tov.OSMajorVersion}.{tov.OSMinorVersion}.{tov.BuildNumber}"
					for hwid in dev.hardware_ids:
						if not hwid.vendor_id or not hwid.device_id:
							continue
						if hwid.device_type == DeviceType.MULTI:
							logger.debug("Skipping device type %s", hwid.device_type)
							continue
						for driver_db in True, False:
							if driver_db:
								hwid_dir: Path = tov_dir / hwid.device_type
							else:
								if hwid.device_type == DeviceType.USB:
									hwid_dir = legacy_usbids_dir
								elif hwid.device_type == DeviceType.HDAUDIO:
									hwid_dir = legacy_hdaudioids_dir
								elif hwid.device_type == DeviceType.PCI:
									hwid_dir = legacy_pciids_dir
								else:
									continue
							link: Path = hwid_dir / hwid.vendor_id / hwid.device_id
							link.parent.mkdir(parents=True, exist_ok=True)
							if link.exists():
								continue
							link.symlink_to(root_path)
							logger.debug("Created link '%s' -> '%s'", link, root_path)

	@rpc_method
	def driver_getSources(
		self: BackendProtocol, clientId: str, productId: str, architecture: str | None = None, osVersion: str | None = None
	) -> list[BinarySource]:
		"""
		Get drivers for product and client.
		"""
		product_id = typeForceProductId(productId)
		client_id = typeForceHostId(clientId)
		depot_dir = Path(DEPOT_DIR)

		if not self.host_getIdents(id=client_id):
			raise BackendMissingDataError(f"Client '{client_id}' not found")
		if not self.product_getIdents(id=product_id):
			raise BackendMissingDataError(f"Product '{product_id}' not found")

		ahohs = self.auditHardwareOnHost_getObjects(hostId=client_id)
		if not ahohs:
			raise BackendMissingDataError(f"No hardware information found for client '{client_id}'")

		if not architecture or not osVersion:
			logger.info("Getting architecture and OS version from WIM image")
			values = self.productPropertyState_getValues(product_ids=product_id, property_ids="image", object_ids=client_id)
			image = values.get(client_id, {}).get(product_id, {}).get("image", [""])[0]
			logger.debug("Product property 'image' for client %r is %r", client_id, image)
			if image:
				image_file, image_name_or_index = image.split(":", 1) if ":" in image else ("install.wim", image)
				image_path = depot_dir / product_id / "images" / image_file
				logger.debug("Image file: %s", image_path)
				if not image_path.exists():
					raise BackendError(f"Image file '{image_path}' from product property 'image' not found")
				for tov in get_target_os_versions(image_path, image_name_or_index):
					logger.info("Using target OS version %s", tov)
					if not architecture:
						architecture = str(tov.Architecture)
					if not osVersion:
						osVersion = f"{tov.OSMajorVersion}.{tov.OSMinorVersion}.{tov.BuildNumber}"
					break

		if not architecture:
			raise BackendError("Missing architecture")
		if not osVersion:
			raise BackendError("Missing OS version")

		tov = INFTargetOSVersion(Architecture=Architecture.from_string(architecture))
		version_parts = osVersion.split(".")
		if len(version_parts) >= 1:
			tov.OSMajorVersion = int(version_parts[0])
			if len(version_parts) >= 2:
				tov.OSMinorVersion = int(version_parts[1])
				if len(version_parts) >= 3:
					tov.BuildNumber = int(version_parts[2])

		client_data_dir = depot_dir / product_id
		base_dir = client_data_dir / "drivers"
		drivers_dir = base_dir / "drivers"
		additional_dir = drivers_dir / "additional"
		by_audit_dir = additional_dir / "byAudit"
		driver_db_dir = base_dir / "driver_db"
		tov_dir = driver_db_dir / tov.Architecture / f"{tov.OSMajorVersion}.{tov.OSMinorVersion}.{tov.BuildNumber}"

		sources = []
		replace_re = re.compile(r'[<>?":|\\/*]')
		sys_vendor = ""
		sys_model = ""
		sys_sku = ""
		board_vendor = ""
		board_model = ""
		for ahoh in ahohs:
			if ahoh.hardwareClass == "COMPUTER_SYSTEM":
				sys_vendor = replace_re.sub("_", ahoh.vendor or "").rstrip("._ ")
				sys_model = replace_re.sub("_", ahoh.model or "").rstrip("._ ")
				sys_sku = replace_re.sub("_", ahoh.sku or "").rstrip("._ ")
				continue
			if ahoh.hardwareClass == "BASE_BOARD":
				board_vendor = replace_re.sub("_", ahoh.vendor or "").rstrip("._ ")
				board_model = replace_re.sub("_", ahoh.model or "").rstrip("._ ")
				continue
			if ahoh.hardwareClass not in ("PCI_DEVICE", "USB_DEVICE", "HDAUDIO_DEVICE"):
				continue
			if not ahoh.vendorId or not ahoh.deviceId:
				continue
			device_type = ahoh.hardwareClass.removesuffix("_DEVICE")
			drv_dir = tov_dir / device_type / ahoh.vendorId / ahoh.deviceId
			if not drv_dir.exists():
				continue

			ahoh_dict = ahoh.to_hash()
			sources.append(
				BinarySource(
					binary_type=BinarySourceBinaryType.WINDOWS_DRIVER,
					access_type=BinarySourceAccessType.DEPOT,
					operation_type=BinarySourceOperationType.RECURSIVE_COPY,
					url=str(drv_dir.relative_to(depot_dir)),
					information={
						"device_type": device_type,
						"vendor_id": ahoh_dict.get("vendorId"),
						"device_id": ahoh_dict.get("deviceId"),
						"vendor_name": ahoh_dict.get("vendor"),
						"device_name": ahoh_dict.get("name"),
					},
				)
			)

		additional_dirs: dict[Path, dict[str, Any]] = {}
		if by_audit_dir.is_dir():
			vendors = []
			if sys_vendor:
				vendors.append(sys_vendor.lower())
			if board_vendor:
				vendors.append(board_vendor.lower())

			models = []
			if sys_model:
				models.append(sys_model.lower())
				if sys_sku and sys_sku in sys_model:
					models.append(sys_model.lower().replace(f"{sys_sku.lower()}", "").replace("()", "").strip())
			if board_model:
				models.append(board_model.lower())

			if vendors and models:
				logger.notice("Looking for byAudit drivers for vendors %r and models %r", vendors, models)
				for vendor_dir in by_audit_dir.iterdir():
					if vendor_dir.name.lower().rstrip("._ ") in vendors:
						logger.info("Found matching byAudit driver vendor directory %r", vendor_dir.name)
						for model_dir in vendor_dir.iterdir():
							if model_dir.is_dir() and model_dir.name.lower().rstrip("._ ") in models:
								logger.info("Found matching byAudit driver model directory %r", model_dir.name)
								additional_dirs[model_dir] = {
									"sys_vendor": sys_vendor,
									"sys_model": sys_model,
									"board_vendor": board_vendor,
									"board_model": board_model,
									"by_audit_vendor_dir_name": vendor_dir.name,
									"by_audit_model_dir_name": model_dir.name,
								}
								break
						break

		additional_drivers: list[str] = (
			self.productPropertyState_getValues(
				product_ids=product_id, property_ids="additional_drivers", object_ids=client_id, with_defaults=True
			)
			.get(client_id, {})
			.get(product_id, {})
			.get("additional_drivers", [])
		)
		if additional_drivers:
			logger.notice("Found configured additional drivers for client %r and product %r: %r", client_id, product_id, additional_drivers)
			for dirname in additional_drivers:
				additional_dirs[additional_dir / dirname] = {"additional_dir": dirname}

		for driver_dir, information in additional_dirs.items():
			if not driver_dir.is_dir():
				logger.warning("Additional driver directory '%s' does not exist, skipping", driver_dir)
				continue

			inf_files = list(driver_dir.glob("**/*.[Ii][Nn][Ff]"))
			if not inf_files:
				logger.warning("No inf files found in additional driver directory '%s', skipping", driver_dir)
				continue

			for inf_file in inf_files:
				logger.info("Found additional inf file '%s'", inf_file)
				sources.append(
					BinarySource(
						binary_type=BinarySourceBinaryType.WINDOWS_DRIVER,
						access_type=BinarySourceAccessType.DEPOT,
						operation_type=BinarySourceOperationType.RECURSIVE_COPY,
						url=str(inf_file.parent.relative_to(depot_dir)),
						information=information,
					)
				)

		return sources
