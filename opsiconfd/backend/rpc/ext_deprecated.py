# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods wim
"""
from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any, Dict, List, Protocol

from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceDomain,
	forceHostId,
	forceHostname,
)

from . import deprecated_rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtDeprecatedMixin(Protocol):
	@deprecated_rpc_method(alternative_method="backend_createBase")
	def createOpsiBase(self: BackendProtocol) -> None:  # pylint: disable=invalid-name
		self.backend_createBase()

	@deprecated_rpc_method(alternative_method="host_createOpsiConfigserver")
	def createServer(  # pylint: disable=invalid-name
		self: BackendProtocol, serverName: str, domain: str, description: str = None, notes: str = None
	) -> str:
		host_id = forceHostId(".".join((forceHostname(serverName), forceDomain(domain))))
		self.host_createOpsiConfigserver(id=host_id, description=description, notes=notes)
		return host_id

	@deprecated_rpc_method(alternative_method="host_delete")
	def deleteClient(self: BackendProtocol, clientId: str) -> None:  # pylint: disable=invalid-name
		self.host_delete(id=forceHostId(clientId))

	@deprecated_rpc_method(alternative_method="host_delete")
	def deleteDepot(self: BackendProtocol, depotId: str) -> None:  # pylint: disable=invalid-name
		self.host_delete(id=forceHostId(depotId))

	@deprecated_rpc_method(alternative_method="group_delete")
	def deleteGroup(self: BackendProtocol, groupId: str) -> None:  # pylint: disable=invalid-name
		self.group_delete(id=groupId)

	@deprecated_rpc_method
	def deleteProductDependency(  # pylint: disable=invalid-name,too-many-arguments
		self,
		productId: str,
		action: str = "",
		requiredProductId: str = "",
		requiredProductClassId: str = "",
		requirementType: str = "",
		depotIds: List[str] = None,
	) -> None:
		if requiredProductClassId:
			warnings.warn("The argument 'requiredProductClassId' is obsolete and has no effect.", DeprecationWarning)
		if requirementType:
			warnings.warn("The argument 'requirementType' is obsolete and has no effect.", DeprecationWarning)

		for product_on_depot in self.productOnDepot_getObjects(productId=productId, depotId=depotIds or []):
			self.productDependency_delete(
				productId=product_on_depot.productId,
				productVersion=product_on_depot.productVersion,
				packageVersion=product_on_depot.packageVersion,
				productAction=action or None,
				requiredProductId=requiredProductId or None,
			)

	@deprecated_rpc_method(alternative_method="host_delete")
	def deleteServer(self: BackendProtocol, serverId: str) -> None:  # pylint: disable=invalid-name
		self.host_delete(id=forceHostId(serverId))

	@deprecated_rpc_method
	def setHostLastSeen(self: BackendProtocol, hostId: str, timestamp: str) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host '{hostId}' not found")
		hosts[0].setLastSeen(timestamp)
		self.host_updateObject(hosts[0])

	@deprecated_rpc_method(alternative_method="getClients")
	def getClients_listOfHashes(  # pylint: disable=invalid-name,too-many-arguments
		self,
		serverId: str = None,
		depotIds: List[str] = None,
		groupId: str = None,
		productId: str = None,
		installationStatus: str = None,
		actionRequest: str = None,
		productVersion: str = None,
		packageVersion: str = None,
		hwFilter: dict = None,
	) -> List[Dict[str, Any]]:
		if (
			serverId  # pylint: disable=too-many-boolean-expressions
			or depotIds
			or groupId
			or productId
			or installationStatus
			or actionRequest
			or productVersion
			or packageVersion
			or hwFilter
		):
			raise RuntimeError("These parameters have been deprecated")

		return self.getClients()

	@deprecated_rpc_method(alternative_method="getClientIDs")
	def getClientIds_list(  # pylint: disable=invalid-name,too-many-arguments
		self,
		serverId: str = None,
		depotIds: List[str] = None,
		groupId: str = None,
		productId: str = None,
		installationStatus: str = None,
		actionRequest: str = None,
		productVersion: str = None,
		packageVersion: str = None,
		hwFilter: dict = None,
	) -> List[str]:
		if not (
			serverId
			or depotIds
			or groupId
			or productId
			or installationStatus
			or actionRequest
			or productVersion
			or packageVersion
			or hwFilter
		):
			return self.getClientIDs()
		if depotIds:
			return self.getClientsOnDepot(depotIds)
		if productId and installationStatus:
			return self.getClientsWithProducts(productId, installationStatus=installationStatus)
		if productId:
			return self.getClientsWithProducts(productId)
		if actionRequest:
			return self.getClientsWithActionRequest(actionRequest)

		raise RuntimeError("Missing parameters for mapping getClientIds_list to replacing method.")
