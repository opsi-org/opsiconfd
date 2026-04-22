# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.reporting
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, cast

from opsi.opsi.service.model.object import OpsiClient

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


OPERATING_SYSTEM_TYPE = Literal["windows", "linux", "macos"]
ARCHITECURE = Literal["x86", "x64", "arm64"]


@dataclass
class Client:
	id: str
	hardwareAddress: str | None = None
	ipAddress: str | None = None
	inventoryNumber: str | None = None
	created: str | None = None
	lastSeen: str | None = None
	systemUUID: str | None = None
	device_vendor: str | None = None
	device_model: str | None = None
	device_sn: str | None = None
	device_ram: float | None = None
	device_processor: str | None = None
	operating_system_type: OPERATING_SYSTEM_TYPE | None = None
	operating_system_architecture: ARCHITECURE | None = None
	operating_system: str | None = None


class RPCReportingMixin(Protocol):
	@rpc_method()
	def reporting_getClients(self: BackendProtocol, depots: list[str] = []) -> list[Client]:
		clients: dict[str, Client] = {}
		client: OpsiClient
		depot_to_client = self.configState_getClientToDepotserver(depotIds=depots)
		client_ids = set()
		if depots:
			for obj in depot_to_client:
				client_ids.add(obj.get("clientId"))

		for client in self.host_getObjects(type="OpsiClient"):
			if client_ids and client.id not in client_ids:
				continue
			kwargs = client.to_hash()
			del kwargs["type"]
			del kwargs["opsiHostKey"]
			del kwargs["description"]
			del kwargs["notes"]
			del kwargs["oneTimePassword"]
			clients[client.id] = Client(**kwargs)
			clients[client.id].id = client.id

		if not clients:
			return []

		with self._mysql.session() as session:
			for row in session.execute(
				"""
				SELECT hccs.hostId, hdcs.vendor, hdcs.model, hdc.chassisType, hccs.serialNumber, hccs.totalPhysicalMemory, hdp.name
				FROM HARDWARE_CONFIG_COMPUTER_SYSTEM AS hccs
				JOIN HARDWARE_DEVICE_COMPUTER_SYSTEM AS hdcs ON hdcs.hardware_id = hccs.hardware_id
				LEFT JOIN HARDWARE_CONFIG_CHASSIS AS hcc ON hcc.hostId = hccs.hostId
				LEFT JOIN HARDWARE_DEVICE_CHASSIS AS hdc ON hdc.hardware_id = hcc.hardware_id
				LEFT JOIN HARDWARE_CONFIG_PROCESSOR as hcp ON hcp.hostId = hccs.hostId
				LEFT JOIN HARDWARE_DEVICE_PROCESSOR AS hdp ON hdp.hardware_id = hcp.hardware_id
				WHERE hccs.hostId in :client_ids
				""",
				params={"client_ids": list(clients)},
			).fetchall():
				clients[row[0]].device_vendor = row[1]
				clients[row[0]].device_model = row[2]
				clients[row[0]].device_sn = row[4] or None
				clients[row[0]].device_ram = row[5] / 1024 / 1024 if row[5] else None
				clients[row[0]].device_processor = row[6] or None

			for row in session.execute(
				"""
				SELECT sc.clientId, s.name, s.subVersion, s.architecture
				FROM SOFTWARE_CONFIG AS sc
				JOIN SOFTWARE AS s ON s.software_id = sc.software_id
				WHERE s.isOperatingSystem = 1 and sc.clientId in :client_ids
				""",
				params={"client_ids": list(clients)},
			).fetchall():
				clients[row[0]].operating_system = row[1]
				clients[row[0]].operating_system_type = "linux" if row[2] == "lin:" else "macos" if row[2] == "mac:" else "windows"
				clients[row[0]].operating_system_architecture = cast(ARCHITECURE, row[3]) if row[3] else None

		return list(clients.values())
