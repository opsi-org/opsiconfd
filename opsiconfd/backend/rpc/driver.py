# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.driver
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import BackendError, BackendMissingDataError
from opsicommon.package.wim import wim_info
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


def get_target_os_versions(client_data_dir: Path) -> list[INFTargetOSVersion]:
	target_os_versions: dict[str, INFTargetOSVersion] = {}
	wim_files = set()
	for image_dir in ("images", "installfiles/sources"):
		image_path = client_data_dir / image_dir
		if not image_path.exists():
			continue
		for file in image_path.iterdir():
			if file.suffix.lower() not in (".wim", ".esd", ".swm"):
				continue
			if file.suffix.lower() == ".swm" and re.match(r"\d+\.swm", file.stem):
				# Only process first part of split wim
				continue
			logger.info("Processing WIM file '%s'", file)
			wim_files.add(file)
			images = wim_info(file).images
			if not images:
				continue
			windows_info = images[0].windows_info
			if not windows_info:
				continue
			tov = INFTargetOSVersion(
				Architecture=Architecture.from_string(windows_info.architecture),
				OSMajorVersion=windows_info.major_version,
				OSMinorVersion=windows_info.minor_version,
				BuildNumber=windows_info.build,
			)
			target_os_versions[f"{tov.Architecture}_{tov.OSMajorVersion}_{tov.OSMinorVersion}_{tov.BuildNumber}"] = tov
		break

	if not wim_files:
		raise BackendError(f"No WIM files found in '{client_data_dir}'")

	return list(target_os_versions.values())


class RPCDriverMixin(Protocol):
	@rpc_method
	def driver_updateDatabase(self: BackendProtocol, productId: str) -> None:
		"""
		Create the driver integration structure in the products depot directory.
		"""
		product_id = typeForceProductId(productId)
		client_data_dir = Path(DEPOT_DIR) / product_id
		target_os_versions = get_target_os_versions(client_data_dir)
		if not target_os_versions:
			raise BackendError(f"No target OS versions found in images for product '{product_id}'")

		drivers_dir = client_data_dir / "drivers"
		driver_db_dir = client_data_dir / "driver_db"
		if driver_db_dir.exists():
			shutil.rmtree(driver_db_dir)
		inf_re = re.compile(".*\.inf", re.IGNORECASE)

		for root, _dirs, files in os.walk(drivers_dir):
			for filename in files:
				if inf_re.match(filename):
					file_path = Path(root) / filename
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
								hwid_dir: Path = tov_dir / hwid.device_type / hwid.vendor_id
								hwid_dir.mkdir(parents=True, exist_ok=True)
								link: Path = hwid_dir / hwid.device_id
								if link.exists():
									continue
								link.symlink_to(root)
								logger.debug("Created link '%s' -> '%s'", link, root)

	@rpc_method
	def driver_getSources(self: BackendProtocol, productId: str, architecture: str, osVersion: str, clientId: str) -> list[BinarySource]:
		"""
		Get drivers for product and client.
		"""
		product_id = typeForceProductId(productId)
		client_id = typeForceProductId(clientId)
		tov = INFTargetOSVersion(Architecture=Architecture.from_string(architecture))
		version_parts = osVersion.split(".")
		if len(version_parts) >= 1:
			tov.OSMajorVersion = int(version_parts[0])
			if len(version_parts) >= 2:
				tov.OSMinorVersion = int(version_parts[1])
				if len(version_parts) >= 3:
					tov.BuildNumber = int(version_parts[2])

		ahohs = self.auditHardwareOnHost_getObjects(hostId=client_id)
		if not ahohs:
			raise BackendMissingDataError(f"No hardware information found for client '{client_id}'")

		depot_dir = Path(DEPOT_DIR)
		driver_db_dir = depot_dir / product_id / "driver_db"
		tov_dir = driver_db_dir / tov.Architecture / f"{tov.OSMajorVersion}.{tov.OSMinorVersion}.{tov.BuildNumber}"

		sources = []
		for ahoh in ahohs:
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
		return sources
