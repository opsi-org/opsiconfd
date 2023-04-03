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
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceDomain,
	forceHostId,
	forceHostname,
)

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtDeprecatedMixin(Protocol):
	@rpc_method(deprecated=True, alternative_method="backend_createBase", check_acl=False)
	def createOpsiBase(self: BackendProtocol) -> None:  # pylint: disable=invalid-name
		self.backend_createBase()

	@rpc_method(deprecated=True, alternative_method="host_createOpsiConfigserver", check_acl=False)
	def createServer(  # pylint: disable=invalid-name
		self: BackendProtocol, serverName: str, domain: str, description: str | None = None, notes: str | None = None
	) -> str:
		host_id = forceHostId(".".join((forceHostname(serverName), forceDomain(domain))))
		self.host_createOpsiConfigserver(id=host_id, description=description, notes=notes)
		return host_id

	@rpc_method(deprecated=True, alternative_method="host_delete", check_acl=False)
	def deleteClient(self: BackendProtocol, clientId: str) -> None:  # pylint: disable=invalid-name
		self.host_delete(id=forceHostId(clientId))

	@rpc_method(deprecated=True, alternative_method="host_delete", check_acl=False)
	def deleteDepot(self: BackendProtocol, depotId: str) -> None:  # pylint: disable=invalid-name
		self.host_delete(id=forceHostId(depotId))

	@rpc_method(deprecated=True, alternative_method="group_delete", check_acl=False)
	def deleteGroup(self: BackendProtocol, groupId: str) -> None:  # pylint: disable=invalid-name
		self.group_delete(id=groupId)

	@rpc_method(deprecated=True, alternative_method="productDependency_delete")
	def deleteProductDependency(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		productId: str,
		action: str = "",
		requiredProductId: str = "",
		requiredProductClassId: str = "",
		requirementType: str = "",
		depotIds: list[str] | None = None,
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

	@rpc_method(deprecated=True, alternative_method="host_delete", check_acl=False)
	def deleteServer(self: BackendProtocol, serverId: str) -> None:  # pylint: disable=invalid-name
		self.host_delete(id=forceHostId(serverId))

	@rpc_method(deprecated=True, alternative_method="host_updateObject", check_acl=False)
	def setHostLastSeen(self: BackendProtocol, hostId: str, timestamp: str) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host '{hostId}' not found")
		hosts[0].setLastSeen(timestamp)
		self.host_updateObject(hosts[0])

	@rpc_method(deprecated=True, alternative_method="host_getObjects", check_acl=False)
	def getClients_listOfHashes(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		serverId: str | None = None,
		depotIds: list[str] | None = None,
		groupId: str | None = None,
		productId: str | None = None,
		installationStatus: str | None = None,
		actionRequest: str | None = None,
		productVersion: str | None = None,
		packageVersion: str | None = None,
		hwFilter: dict | None = None,
	) -> list[dict[str, Any]]:
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

	@rpc_method(deprecated=True, drop_version="4.4", alternative_method="getClientIDs", check_acl=False)
	def getClientIds_list(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		serverId: str | None = None,
		depotIds: list[str] | None = None,
		groupId: str | None = None,
		productId: str | None = None,
		installationStatus: str | None = None,
		actionRequest: str | None = None,
		productVersion: str | None = None,
		packageVersion: str | None = None,
		hwFilter: dict | None = None,
	) -> list[str]:
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
