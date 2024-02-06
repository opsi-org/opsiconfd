# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods opsi
"""

from __future__ import annotations

import datetime
import os
import subprocess
from typing import TYPE_CHECKING, Protocol

from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.objects import ProductOnClient  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceActionRequest,
	forceHostId,
	forceProductId,
)

from opsiconfd.config import DEPOT_DIR
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtOpsiMixin(Protocol):
	@rpc_method(deprecated=False, alternative_method="productOnClient_updateObjects", check_acl=False)
	def setProductActionRequest(
		self: BackendProtocol, productId: str, clientId: str, actionRequest: str
	) -> None:
		self.setProductState(productId=productId, objectId=clientId, actionRequest=actionRequest)

	@rpc_method(deprecated=False, alternative_method="productOnClient_updateObjects", check_acl=False)
	def setProductActionRequestWithDependencies(
		self: BackendProtocol, productId: str, clientId: str, actionRequest: str
	) -> None:
		"""
		Set the action request `actionRequest` for product with id `productId` on client `clientId`.

		:param productId: Id of the product.
		:type productId: str
		:param clientId: Client that should get the request set.
		:type clientId: str
		:param actionRequest: The request to set.
		:type actionRequest: str
		"""
		productId = forceProductId(productId)
		clientId = forceHostId(clientId)
		actionRequest = forceActionRequest(actionRequest)
		depotId = self.getDepotId(clientId=clientId)
		if not self.productOnDepot_getObjects(depotId=depotId, productId=productId):
			raise BackendMissingDataError(f"Product {productId!r} not found on depot {depotId!r}")

		if res := self.productOnClient_getObjects(clientId=clientId, productId=productId):
			product_on_client = res[0]
			product_on_client.actionRequest = actionRequest
		else:
			product_on_client = ProductOnClient(
				productId=productId,
				productType="LocalbootProduct",
				clientId=clientId,
				installationStatus="not_installed",
				actionRequest=actionRequest,
			)

		self.productOnClient_updateObjectsWithDependencies([product_on_client])

	@rpc_method(deprecated=True, alternative_method="accessControl_userIsReadOnlyUser", check_acl=False)
	def userIsReadOnlyUser(self: BackendProtocol) -> bool:
		return self.accessControl_userIsReadOnlyUser()

	@rpc_method(deprecated=True, check_acl=False)
	def getServiceTime(self: BackendProtocol, utctime: bool = False) -> str:
		if utctime:
			return str(datetime.datetime.utcnow())
		return str(datetime.datetime.now())

	@rpc_method(deprecated=True, alternative_method="auditSoftwareOnClient_getObjects", check_acl=False)
	def getSoftwareAuditDataCount(self: BackendProtocol) -> int:
		"""Get the count of data relevant to the software audit."""
		return len(self.auditSoftware_getObjects()) + len(self.auditSoftwareOnClient_getObjects())

	@rpc_method(deprecated=True, alternative_method="auditHardwareOnHost_getObjects", check_acl=False)
	def getHardwareAuditDataCount(self: BackendProtocol) -> int:
		"""Get the count of data relevant to the hardware audit."""
		return len(self.auditHardware_getObjects()) + len(self.auditHardwareOnHost_getObjects())

	@rpc_method(deprecated=True, check_acl=False)
	def setRights(self: BackendProtocol, path: str | None = None) -> str:
		"""
		Setting rights for a specified path.
		If no path is given it will try to set the rights for the current depot.
		"""
		if not path:
			path = DEPOT_DIR

		if not os.path.exists(path):
			raise IOError(f"The path {path!r} does not exist")

		logger.debug("Going to set rights for path %r", path)
		call_result = subprocess.call(["sudo", "opsi-set-rights", path])
		logger.debug("Finished setting rights. Exit code: %r", call_result)

		if call_result:
			raise RuntimeError(f"Setting rights on {path!r} failed. Did you run 'opsi-setup --patch-sudoers-file'?")

		return f"Changing rights at {path!r} successful."
