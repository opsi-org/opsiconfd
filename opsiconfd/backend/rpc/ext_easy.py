# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods wim
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.types import (  # type: ignore[import]
	forceActionRequestList,
	forceHostIdList,
	forceInstallationStatus,
	forceProductIdList,
)

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtEasyMixin(Protocol):
	@rpc_method(deprecated=True, alternative_method="host_getObjects")
	def getClients(self: BackendProtocol) -> list[dict[str, Any]]:  # pylint: disable=invalid-name
		"""
		Returns a list of client hashes.

		These hashes do not include the fields `type` and `id`.
		They contain the additional field `depotId` with the assigned depot of the client.

		:rtype: [{}, ]
		"""
		timestamp_regex = re.compile(r"^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$")

		def convert_timestamp(timestamp: str | None) -> str:
			if timestamp is None:
				return ""

			match = timestamp_regex.search(timestamp)
			if match:
				return f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}{match.group(5)}{match.group(6)}"

			return timestamp

		client_to_depotservers = {mapping["clientId"]: mapping["depotId"] for mapping in self.configState_getClientToDepotserver()}

		results = []
		for client in self.host_getHashes(type="OpsiClient"):
			client["hostId"] = client["id"]
			client["created"] = convert_timestamp(client.get("created"))
			client["lastSeen"] = convert_timestamp(client.get("lastSeen"))
			client["depotId"] = client_to_depotservers.get(client["id"], "")

			del client["type"]
			del client["id"]

			results.append({k: "" if v is None else v for k, v in client.items()})

		return results

	@rpc_method(deprecated=True, alternative_method="host_getIdents")
	def getClientIDs(self: BackendProtocol) -> list[str]:  # pylint: disable=invalid-name
		"""
		Returns a list of client IDs.

		:rtype: [str, ]
		"""
		return self.host_getIdents(type="OpsiClient")

	@rpc_method(deprecated=True, alternative_method="configState_getClientToDepotserver")
	def getClientsOnDepot(self: BackendProtocol, depotIds: list[str]) -> list[str]:  # pylint: disable=invalid-name
		"""
		Returns a list of client IDs that can be found on the given depots.

		:param depotIds: IDs of depots
		:type depotIds: [str, ]
		:rtype: list
		"""
		depotIds = forceHostIdList(depotIds)
		if not depotIds:
			raise ValueError("No depotIds given")

		return [clientToDepotserver["clientId"] for clientToDepotserver in self.configState_getClientToDepotserver(depotIds=depotIds)]

	@rpc_method(deprecated=True)
	def getClientsWithProducts(  # pylint: disable=invalid-name
		self: BackendProtocol, productIds: list[str], installationStatus: str | None = None
	) -> list[str]:
		"""
		Returns a list of client IDs with the given productIds independent from
		their status.
		This means that this might return clients that had the software in
		the past but not currently.

		If `installationStatus` is set only clients with the given status for the
		products will be returned.

		:param productIds: The products to search for
		:type productIds: [str, ]
		:param installationStatus: a specific status to search
		:type installationStatus: str
		:rtype: [str, ]
		"""
		productIds = forceProductIdList(productIds)
		if not productIds:
			raise ValueError("Missing product ids")

		poc_filter: dict[str, list[str] | str] = {
			"productId": productIds,
		}
		if installationStatus is not None:
			poc_filter["installationStatus"] = forceInstallationStatus(installationStatus)

		return list({poc.clientId for poc in self.productOnClient_getObjects(**poc_filter)})

	@rpc_method(deprecated=True)
	def getClientsWithActionRequest(self: BackendProtocol, actionRequests: list[str]) -> list[str]:  # pylint: disable=invalid-name
		"""
		Returns a list of client IDs that have the given actionRequests set.
		Each client will only be present once in the list of one of the given action requests match.

		:param actionRequests: The action requests to filter for.
		:type actionRequests: str or [str, ]
		:rtype: [str, ]
		"""
		actionRequests = [request for request in forceActionRequestList(actionRequests) if request]
		if not actionRequests:
			raise ValueError("Missing action requests")

		return list({poc.clientId for poc in self.productOnClient_getObjects(actionRequest=actionRequests)})
