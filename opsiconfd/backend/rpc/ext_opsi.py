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

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtOpsiMixin(Protocol):
	@rpc_method(check_acl=False, deprecated=True, alternative_method="productOnClient_updateObjects")
	def setProductActionRequestWithDependencies(  # pylint: disable=invalid-name
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

		if self.product_getObjects(id=productId, type="NetbootProduct"):
			# Handling a netboot product
			logger.debug("Dependency-handling for netboot-products is unsupported. Calling setProductActionRequest instead.")
			self.setProductActionRequest(productId, clientId, actionRequest)
			return

		if actionRequest in ("none", None):
			logger.warning(
				"Dependency-handling for action request '%s' is unsupported. Calling setProductActionRequest instead.", actionRequest
			)
			self.setProductActionRequest(productId, clientId, actionRequest)
			return

		pocExists = False
		found_product_on_clients = []
		for poc in self.productOnClient_getObjects(clientId=clientId):
			if poc.productId == productId:
				logger.debug("productOnClient for requested product found, updating")
				if poc.getActionRequest() != actionRequest:
					poc.setActionRequest(actionRequest)
				pocExists = True
			found_product_on_clients.append(poc)

		if not pocExists:
			logger.debug("requested productOnClient object does not exist, creating")
			found_product_on_clients.append(
				ProductOnClient(
					productId=productId,
					productType="LocalbootProduct",
					clientId=clientId,
					installationStatus="not_installed",
					actionRequest=actionRequest,
				)
			)

		product_on_clients = self.productOnClient_addDependencies(found_product_on_clients)
		pocsToUpdate = [poc for poc in product_on_clients if poc.getActionRequest() not in (None, "none")]
		if pocsToUpdate:
			self.productOnClient_updateObjects(pocsToUpdate)

	@rpc_method(deprecated=True, alternative_method="accessControl_userIsReadOnlyUser")
	def userIsReadOnlyUser(self: BackendProtocol) -> bool:  # pylint: disable=invalid-name
		return self.accessControl_userIsReadOnlyUser()

	@rpc_method(deprecated=True)
	def getServiceTime(self: BackendProtocol, utctime: bool = False) -> str:  # pylint: disable=invalid-name
		if utctime:
			return str(datetime.datetime.utcnow())
		return str(datetime.datetime.now())

	@rpc_method(deprecated=True, alternative_method="auditSoftwareOnClient_getObjects")
	def getSoftwareAuditDataCount(self: BackendProtocol) -> int:  # pylint: disable=invalid-name
		"""Get the count of data relevant to the software audit."""
		return len(self.auditSoftware_getObjects()) + len(self.auditSoftwareOnClient_getObjects())

	@rpc_method(deprecated=True, alternative_method="auditHardwareOnHost_getObjects")
	def getHardwareAuditDataCount(self: BackendProtocol) -> int:  # pylint: disable=invalid-name
		"""Get the count of data relevant to the hardware audit."""
		return len(self.auditHardware_getObjects()) + len(self.auditHardwareOnHost_getObjects())

	@rpc_method(deprecated=True)
	def setRights(self: BackendProtocol, path: str | None = None) -> str:  # pylint: disable=invalid-name
		"""
		Setting rights for a specified path.
		If no path is given it will try to set the rights for the current depot.

		The current implementation requires "sudo opsi-setup --patch-sudoers-file"
		to be run before.
		"""
		if path is None:
			old_depot_path = "/opt/pcbin/install/"
			new_depot_path = "/var/lib/opsi/depot/"
			try:
				if os.path.exists(new_depot_path) and os.path.islink(new_depot_path):
					linked_path = os.readlink(new_depot_path)
					if os.path.isabs(linked_path):
						path = linked_path
					else:
						path = os.path.join(os.path.dirname(new_depot_path), linked_path)
				else:
					path = old_depot_path
			except OSError as oserr:
				if "operation not permitted" in str(oserr).lower():
					path = old_depot_path
				else:
					raise oserr

		if not os.path.exists(path):
			raise IOError(f"The path {path!r} does not exist")

		logger.debug("Going to set rights for path %r", path)
		call_result = subprocess.call(["sudo", "opsi-set-rights", path])
		logger.debug("Finished setting rights. Exit code: %r", call_result)

		if call_result:
			raise RuntimeError(f"Setting rights on {path!r} failed. Did you run 'opsi-setup --patch-sudoers-file'?")

		return f"Changing rights at {path!r} successful."
