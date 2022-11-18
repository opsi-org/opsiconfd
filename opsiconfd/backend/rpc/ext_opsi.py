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
from typing import TYPE_CHECKING, Dict, List, Protocol

import OPSI.SharedAlgorithm  # type: ignore[import]
from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.objects import (  # type: ignore[import]
	LocalbootProduct,
	ProductDependency,
	ProductOnClient,
)
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
	@rpc_method
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

	@rpc_method
	def userIsReadOnlyUser(self: BackendProtocol) -> bool:  # pylint: disable=invalid-name
		return self.accessControl_userIsReadOnlyUser()

	@rpc_method
	def getServiceTime(self: BackendProtocol, utctime: bool = False) -> str:  # pylint: disable=invalid-name
		if utctime:
			return str(datetime.datetime.utcnow())
		return str(datetime.datetime.now())

	@rpc_method
	def getSoftwareAuditDataCount(self: BackendProtocol) -> int:  # pylint: disable=invalid-name
		"""Get the count of data relevant to the software audit."""
		return len(self.auditSoftware_getObjects()) + len(self.auditSoftwareOnClient_getObjects())

	@rpc_method
	def getHardwareAuditDataCount(self: BackendProtocol) -> int:  # pylint: disable=invalid-name
		"""Get the count of data relevant to the hardware audit."""
		return len(self.auditHardware_getObjects()) + len(self.auditHardwareOnHost_getObjects())

	@rpc_method
	def getProductOrdering(  # pylint: disable=invalid-name,too-many-branches
		self: BackendProtocol, depotId: str, sortAlgorithm: str = None
	) -> Dict[str, list]:
		if not sortAlgorithm:
			sortAlgorithm = "algorithm1"
			configs = self.config_getObjects(id="product_sort_algorithm")
			try:
				if "algorithm2" in configs[0].getDefaultValues():
					sortAlgorithm = "algorithm2"
			except IndexError:
				pass

		logger.debug("Using sort algorithm %s", sortAlgorithm)

		products_by_id_and_version: Dict[str, Dict[str, Dict[str, LocalbootProduct]]] = {}
		for product in self.product_getObjects(type="LocalbootProduct"):
			if product.id not in products_by_id_and_version:
				products_by_id_and_version[product.id] = {}
			if product.productVersion not in products_by_id_and_version[product.id]:
				products_by_id_and_version[product.id][product.productVersion] = {}

			products_by_id_and_version[product.id][product.productVersion][product.packageVersion] = product

		products_dependencies_by_id_and_version: Dict[str, Dict[str, Dict[str, List[ProductDependency]]]] = {}
		for prod_dep in self.productDependency_getObjects(productAction="setup"):
			if prod_dep.productId not in products_dependencies_by_id_and_version:
				products_dependencies_by_id_and_version[prod_dep.productId] = {}
			if prod_dep.productVersion not in products_dependencies_by_id_and_version[prod_dep.productId]:
				products_dependencies_by_id_and_version[prod_dep.productId][prod_dep.productVersion] = {}
			if prod_dep.packageVersion not in products_dependencies_by_id_and_version[prod_dep.productId][prod_dep.productVersion]:
				products_dependencies_by_id_and_version[prod_dep.productId][prod_dep.productVersion][prod_dep.packageVersion] = []

			products_dependencies_by_id_and_version[prod_dep.productId][prod_dep.productVersion][prod_dep.packageVersion].append(prod_dep)

		available_products = []
		product_dependencies = []
		productIds = []
		for productOnDepot in self.productOnDepot_getObjects(depotId=depotId, productType="LocalbootProduct"):
			product = (
				products_by_id_and_version.get(productOnDepot.productId, {})
				.get(productOnDepot.productVersion, {})
				.get(productOnDepot.packageVersion)
			)
			if not product:
				continue
			available_products.append(product)
			productIds.append(product.id)
			if not product.setupScript:
				continue
			product_dependencies.extend(
				products_dependencies_by_id_and_version.get(productOnDepot.productId, {})
				.get(productOnDepot.productVersion, {})
				.get(productOnDepot.packageVersion, [])
			)

		productIds.sort()

		if sortAlgorithm == "algorithm1":
			sortedList = OPSI.SharedAlgorithm.generateProductSequence_algorithm1(available_products, product_dependencies)
		else:
			sortedList = OPSI.SharedAlgorithm.generateProductSequence_algorithm2(available_products, product_dependencies)

		return {"not_sorted": productIds, "sorted": sortedList}

	@rpc_method
	def setRights(self: BackendProtocol, path: str = None) -> str:  # pylint: disable=invalid-name
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
