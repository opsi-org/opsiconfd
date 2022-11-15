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
from typing import TYPE_CHECKING, Any, Dict, List, Protocol

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
	@rpc_method
	def getClients(self: BackendProtocol) -> List[Dict[str, Any]]:  # pylint: disable=invalid-name
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

			match = timestamp_regex.search(client.get("created", ""))
			if match:
				return f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}{match.group(5)}{match.group(6)}"

			return timestamp

		client_to_depotservers = {
			mapping['clientId']: mapping['depotId']
			for mapping in
			self.configState_getClientToDepotserver()
		}

		results = []
		for client in self.host_getHashes(type='OpsiClient'):
			client['hostId'] = client['id']
			client['created'] = convert_timestamp(client.get('created'))
			client['lastSeen'] = convert_timestamp(client.get('lastSeen'))
			client['depotId'] = client_to_depotservers.get(client['id'], "")

			del client['type']
			del client['id']

			results.append({k: "" if v is None else v for k, v in client.items()})  # pylint: disable=loop-invariant-statement

		return results

	@rpc_method
	def getClientIDs(self: BackendProtocol) -> List[str]:  # pylint: disable=invalid-name
		"""
		Returns a list of client IDs.

		:rtype: [str, ]
		"""
		return self.host_getIdents(type="OpsiClient")

	@rpc_method
	def getClientsOnDepot(self: BackendProtocol, depotIds: List[str]) -> List[str]:  # pylint: disable=invalid-name
		"""
		Returns a list of client IDs that can be found on the given depots.

		:param depotIds: IDs of depots
		:type depotIds: [str, ]
		:rtype: list
		"""
		depotIds = forceHostIdList(depotIds)
		if not depotIds:
			raise ValueError("No depotIds given")

		return [
			clientToDepotserver['clientId']
			for clientToDepotserver
			in self.configState_getClientToDepotserver(depotIds=depotIds)
		]

	@rpc_method
	def getClientsWithProducts(self: BackendProtocol, productIds: List[str], installationStatus: str = None) -> List[str]:  # pylint: disable=invalid-name
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

		poc_filter = {
			"productId": productIds,
		}
		if installationStatus is not None:
			poc_filter['installationStatus'] = forceInstallationStatus(installationStatus)

		return list({poc.clientId for poc in self.productOnClient_getObjects(**poc_filter)})

	@rpc_method
	def getClientsWithActionRequest(self: BackendProtocol, actionRequests: List[str]) -> List[str]:  # pylint: disable=invalid-name
		"""
		Returns a list of client IDs that have the given actionRequests set.
		Each client will only be present once in the list of one of the given action requests match.

		:param actionRequests: The action requests to filter for.
		:type actionRequests: str or [str, ]
		:rtype: [str, ]
		"""
		actionRequests = [
			request for request
			in forceActionRequestList(actionRequests)
			if request
		]
		if not actionRequests:
			raise ValueError("Missing action requests")

		return list({poc.clientId for poc in self.productOnClient_getObjects(actionRequest=actionRequests)})
