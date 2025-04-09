# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.boot
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from opsicommon.objects import OpsiClient
from opsicommon.types import forceHardwareAddress, forceHostId, forceUUIDString

from opsiconfd.config import BOOT_DIR, DEPOT_DIR
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol

BOOTIMAGE_PATH = Path(BOOT_DIR) / "opsi/opsi-linux-bootimage"


@dataclass(kw_only=True, slots=True)
class BootConfig:
	pxe_boot_server: str | None = None
	pxe_boot_filename: str | None = None
	grub_config: str | None = None
	linux_bootimage_kernel_params: dict[str, str | None] | None = None


class RPCBootMixin(Protocol):
	def _get_default_boot_config(
		self: BackendProtocol,
		ip_version: int | None = None,
		architecture: Literal["x86", "x64", "arm", "arm64"] | None = None,
		bios_type: Literal["UEFI", "BIOS"] | None = None,
		protocol: Literal["TFTP", "HTTP"] | None = None,
	) -> BootConfig:
		return BootConfig(pxe_boot_server=None, pxe_boot_filename=None, grub_config=None, linux_bootimage_kernel_params=None)

	@rpc_method
	def boot_getConfig(
		self: BackendProtocol,
		ip_version: int | None = None,
		architecture: Literal["x86", "x64", "arm", "arm64"] | None = None,
		bios_type: Literal["UEFI", "BIOS"] | None = None,
		protocol: Literal["TFTP", "HTTP"] | None = None,
		client_id: str | None = None,
		system_uuid: str | None = None,
		hardware_address: str | None = None,
	) -> BootConfig:
		"""
		Get the boot configuration for a client.
		"""
		self._check_role("admin")

		if not client_id and not hardware_address and not system_uuid:
			logger.info("No clientId, hardware_address or system_uuid given, returning default boot config")
			return self._get_default_boot_config(ip_version=ip_version, bios_type=bios_type, protocol=protocol)

		client: OpsiClient | None = None
		if client_id:
			client_id = forceHostId(client_id)
			clients = self.host_getObjects(type="OpsiClient", id=client_id)
			if clients:
				client = clients[0]
				logger.debug("Found client by clientId: %r", client)
			else:
				logger.info("Client not found by clientId")

		if not client and system_uuid:
			system_uuid = forceUUIDString(system_uuid)
			clients = self.host_getObjects(type="OpsiClient", systemUUID=system_uuid)
			if clients:
				client = clients[0]
				logger.debug("Found client by system_uuid: %r", client)
			else:
				logger.info("Client not found by system_uuid")

		if not client and hardware_address:
			hardware_address = forceHardwareAddress(hardware_address)
			clients = self.host_getObjects(type="OpsiClient", hardwareAddress=hardware_address)
			if clients:
				client = clients[0]
				logger.debug("Found client by hardware_address: %r", client)
			else:
				logger.info("Client not found by hardware_address")

		if not client:
			logger.info("Client not found, returning default boot config")
			return self._get_default_boot_config(ip_version=ip_version, bios_type=bios_type, protocol=protocol)

		depot_id = self.configState_getClientToDepotserver(clientIds=client_id)[0]["depotId"]
		with self._mysql.session() as session:
			result = session.execute(
				"""
				SELECT
					p.productId,
					p.productVersion,
					p.packageVersion,
					p.priority,
					p.pxeConfigTemplate
				FROM PRODUCT AS p
				JOIN PRODUCT_ON_DEPOT AS pod ON pod.productId = p.productId AND pod.productVersion = p.productVersion AND pod.packageVersion = p.packageVersion
				JOIN PRODUCT_ON_CLIENT AS poc ON poc.productId = p.productId
				WHERE
					p.`type` = "NetbootProduct" AND
					poc.actionRequest IN ("setup", "uninstall", "always", "once", "custom") AND
					poc.clientId = :client_id AND
					pod.depotId = :depot_id
				ORDER BY
					p.priority DESC
				""",
				params={"client_id": client.id, "depot_id": depot_id},
			).fetchall()
		if not result:
			logger.info("No NetbootProduct action found for client %r, returning default boot config", client.id)
			return self._get_default_boot_config(ip_version=ip_version, bios_type=bios_type, protocol=protocol)

		boot_config = BootConfig()

		# Get GRUB config
		if bios_type == "UEFI":
			boot_config.pxe_boot_filename = str(BOOTIMAGE_PATH / "loader/shimx64.efi.signed")
		else:
			boot_config.pxe_boot_filename = str(BOOTIMAGE_PATH / "loader/opsi-netboot.pxe")

		product_info = result[0]
		pxe_config_template = product_info["pxeConfigTemplate"]
		template_file = BOOTIMAGE_PATH / "cfg" / "install-grub-x64"
		if pxe_config_template:
			template_file = Path(product_info["pxeConfigTemplate"])
			if not template_file.is_absolute():
				template_file = Path(DEPOT_DIR) / product_info["productId"] / template_file
				if not template_file.exists():
					template_file = BOOTIMAGE_PATH / "cfg" / template_file

		boot_config.grub_config = template_file.read_text(encoding="utf-8")

		# Get opsi linux bootimage kernel parameters
		client_config = self.configState_getValues(config_ids=["clientconfig.configserver.url"], object_ids=[client.id])
		service_url = client_config.get(client.id, {}).get("clientconfig.configserver.url", [None])[0]
		boot_config.linux_bootimage_kernel_params = {
			"pckey": client.opsiHostKey,
			"hn": client.id.split(".")[0],
			"dn": ".".join(client.id.split(".")[1:]),
			"product": product_info["productId"],
			"macaddress": client.hardwareAddress,
			"service": service_url,
		}

		return boot_config
