# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods admin tasks
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Protocol

from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.objects import ProductOnClient  # type: ignore[import]
from opsicommon.types import forceActionRequest, forceProductId  # type: ignore[import]

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtAdminTasksMixin(Protocol):
	@rpc_method(deprecated=True, check_acl=False)
	def setActionRequestWhereOutdated(  # pylint: disable=invalid-name
		self: BackendProtocol,
		actionRequest: str,
		productId: str,  # pylint: disable=invalid-name
	) -> set[str]:
		"""
		Set the specified `actionRequest` at every client that has not the
		version of the product with the given `productId` installed.
		The version is compared between the version installed on the client
		and the one available on the depot.

		:return: The IDs of clients where the actionRequest has been set.
		:rtype: set
		"""
		product_id = forceProductId(productId)
		action_request = forceActionRequest(actionRequest)

		if not self.product_getObjects(id=product_id):
			raise BackendMissingDataError(f"No product with id {product_id!r}")

		clients_to_update = self.getClientsWithOutdatedProduct(product_id)
		for client_id in clients_to_update:
			self.setProductActionRequest(product_id, client_id, action_request)

		return clients_to_update

	@rpc_method(deprecated=True, check_acl=False)
	def getClientsWithOutdatedProduct(self: BackendProtocol, productId: str) -> set[str]:  # pylint: disable=invalid-name
		"""
		Get clients where the product with id `productId` is outdated.
		This does only take clients into account where the 'installationStatus'
		is set and is neither 'not_installed', 'unknown' nor 'none'.

		:return: The IDs of clients with an outdated version installed.
		:rtype: set
		"""
		product_id = forceProductId(productId)

		depot_to_clients = defaultdict(set)
		for client_to_depot in self.configState_getClientToDepotserver():
			depot_to_clients[client_to_depot["depotId"]].add(client_to_depot["clientId"])

		updated_clients = set()
		unwanted_status = frozenset(["not_installed", "none", "unknown"])
		for depot, client_ids in depot_to_clients.items():
			if not client_ids:
				continue

			for product_on_depot in self.productOnDepot_getObjects(productId=product_id, depotId=depot):
				logger.debug("Checking %s...", product_on_depot)
				for product_on_client in self.productOnClient_getObjects(clientId=client_ids, productId=product_on_depot.productId):
					if not product_on_client.installationStatus or product_on_client.installationStatus in unwanted_status:
						logger.debug("Skipping %s", product_on_client)
						continue

					if (
						product_on_client.productVersion != product_on_depot.productVersion
						or product_on_client.packageVersion != product_on_depot.packageVersion
					):
						logger.debug("Version difference at %s", product_on_client)
						updated_clients.add(product_on_client.clientId)

		return updated_clients

	@rpc_method(deprecated=True, check_acl=False)
	def setActionRequestWhereOutdatedWithDependencies(  # pylint: disable=invalid-name
		self: BackendProtocol, actionRequest: str, productId: str
	) -> set[str]:
		"""
		Set the specified `actionRequest` for the given `productId` and
		dependencies at every client that hasn't got the current version
		installed.
		The version is compared between the version installed on the client
		and the one available on the depot.

		:return: The IDs of clients where the actionRequest has been set.
		:rtype: set
		"""
		product_id = forceProductId(productId)
		action_request = forceActionRequest(actionRequest)

		if not self.product_getObjects(id=product_id):
			raise BackendMissingDataError(f"No product with id {product_id!r}")

		clients_to_update = self.getClientsWithOutdatedProduct(product_id)
		for client_id in clients_to_update:
			self.setProductActionRequestWithDependencies(product_id, client_id, action_request)

		return clients_to_update

	@rpc_method(deprecated=True, check_acl=False)
	def setupWhereNotInstalled(self: BackendProtocol, productId: str) -> set[str]:  # pylint: disable=invalid-name
		"""
		Sets the action request for the product with `productId` to 'setup'
		on all clients where the status of the product is not 'installed'.

		The action request will only be set if the depot the client is assigend
		to has a product installed where 'setup' can be set.

		:return: the ID of all clients that have been processed.
		:rtype: set
		"""
		product_id = forceProductId(productId)

		products = frozenset(self.product_getObjects(id=product_id))
		if not products:
			raise BackendMissingDataError(f"No product with id {product_id!r}")

		depot_to_clients = defaultdict(set)
		for client_to_depot in self.configState_getClientToDepotserver():
			depot_to_clients[client_to_depot["depotId"]].add(client_to_depot["clientId"])

		clients_to_setup = set()
		for pod in self.productOnDepot_getObjects(productId=product_id):
			for product in products:
				if (
					product.packageVersion == pod.packageVersion
					and product.productVersion == pod.productVersion
					and product.getSetupScript()
				):
					try:
						for client_id in depot_to_clients[pod.depotId]:
							clients_to_setup.add(client_id)
					except KeyError as notfound:
						logger.debug("%s not found: %s", pod.depotId, notfound)

		if not clients_to_setup:
			logger.info("No clients found where 'setup' is possible.")
			return set()

		logger.debug("Clients possible to 'setup': %s", clients_to_setup)
		clients_with_product_installed = set(
			poc.clientId
			for poc in self.productOnClient_getObjects(
				["clientId"], productId=product_id, clientId=clients_to_setup, installationStatus="installed"
			)
		)
		clients_to_setup.difference_update(clients_with_product_installed)

		logger.debug("Clients to 'setup': %s", clients_to_setup)
		for client_id in clients_to_setup:
			self.setProductActionRequest(product_id, client_id, "setup")

		return clients_to_setup

	@rpc_method(deprecated=True, check_acl=False)
	def updateWhereInstalled(self: BackendProtocol, productId: str) -> set[str]:  # pylint: disable=invalid-name
		"""
		Set the product with the id `productId` to 'update' on every client
		where the installation status is 'installed'.

		The action request will only be set if the depot the client is assigend
		to has a product installed where 'update' can be set.

		:return: the ID of all clients that have been processed.
		:rtype: set
		"""
		product_id = forceProductId(productId)

		products = self.product_getObjects(id=product_id)
		if not products:
			raise BackendMissingDataError(f"No product with id {product_id!r} found")

		clients_with_product_installed = {
			poc.clientId for poc in self.productOnClient_getObjects(productId=product_id, installationStatus="installed")
		}
		if not clients_with_product_installed:
			logger.notice("No clients with product %s installed.", product_id)
			return set()

		depot_to_clients = defaultdict(set)
		for client_to_depot in self.configState_getClientToDepotserver():
			depot_to_clients[client_to_depot["depotId"]].add(client_to_depot["clientId"])

		clients_to_update = set()
		for product in products:
			logger.debug("Processing %s", product)

			if product.getUpdateScript():
				pods = self.productOnDepot_getObjects(
					productId=product.id, productVersion=product.productVersion, packageVersion=product.packageVersion
				)

				for depot in (pod.depotId for pod in pods):
					for client_id in (c for c in depot_to_clients[depot] if c in clients_with_product_installed):
						clients_to_update.add(client_id)

		logger.debug("Clients to 'update': %s", clients_to_update)
		for client_id in clients_to_update:
			self.setProductActionRequest(product_id, client_id, "update")

		return clients_to_update

	@rpc_method(deprecated=True, check_acl=False)
	def uninstallWhereInstalled(self: BackendProtocol, productId: str) -> set[str]:  # pylint: disable=invalid-name
		"""
		Set the product with the id `productId` to 'uninstall' on every client
		where the installation status is 'installed'.

		The action request will only be set if the depot the client is assigend
		to has a product installed where 'uninstall' can be set.

		:return: the ID of all clients that have been processed.
		:rtype: set
		"""
		product_id = forceProductId(productId)

		products = self.product_getObjects(id=product_id)
		if not products:
			raise BackendMissingDataError(f"No product with id {product_id!r}")

		clients_with_product_installed = {
			poc.clientId for poc in self.productOnClient_getObjects(productId=product_id, installationStatus="installed")
		}
		if not clients_with_product_installed:
			logger.notice("No clients have %s installed.", product_id)
			return set()

		depot_to_clients = defaultdict(set)
		for client_to_depot in self.configState_getClientToDepotserver():
			depot_to_clients[client_to_depot["depotId"]].add(client_to_depot["clientId"])

		clients_to_uninstall = set()
		for product in products:
			logger.debug("Processing %s...", product)
			if product.getUninstallScript():
				pods = self.productOnDepot_getObjects(
					productId=product.id, productVersion=product.productVersion, packageVersion=product.packageVersion
				)

				for depot in (pod.depotId for pod in pods):
					for client_id in (c for c in depot_to_clients[depot] if c in clients_with_product_installed):
						clients_to_uninstall.add(client_id)

		logger.debug("Clients to 'uninstall': %s", clients_to_uninstall)
		for client_id in clients_to_uninstall:
			self.setProductActionRequest(product_id, client_id, "uninstall")

		return clients_to_uninstall

	@rpc_method(deprecated=True, check_acl=False)
	def setupWhereInstalled(self: BackendProtocol, productId: str) -> set[str]:  # pylint: disable=invalid-name
		"""
		Set the product with the id `productId` to 'setup' on every client
		where the installation status is 'installed'.

		The action request will only be set if the depot the client is assigend
		to has a product installed where 'setup' can be set.

		:return: the ID of all clients that have been processed.
		:rtype: set
		"""
		product_id = forceProductId(productId)

		products = self.product_getObjects(id=productId)
		if not products:
			raise BackendMissingDataError(f"No product with id {product_id!r}")

		clients_with_product_installed = {
			poc.clientId for poc in self.productOnClient_getObjects(productId=product_id, installationStatus="installed")
		}
		if not clients_with_product_installed:
			logger.notice("No clients have %s installed.", product_id)
			return set()

		depot_to_clients = defaultdict(set)
		for client_to_depot in self.configState_getClientToDepotserver():
			depot_to_clients[client_to_depot["depotId"]].add(client_to_depot["clientId"])

		product_type = None
		clients_to_setup = set()
		for product in products:
			product_type = product.getType()
			logger.debug("Processing %s...", product)
			if product.getSetupScript():
				pods = self.productOnDepot_getObjects(
					productId=product.id, productVersion=product.productVersion, packageVersion=product.packageVersion
				)

				for depot in (pod.depotId for pod in pods):
					for client_id in (c for c in depot_to_clients[depot] if c in clients_with_product_installed):
						clients_to_setup.add(client_id)

		assert product_type
		logger.debug("Clients to 'setup': %s", clients_to_setup)
		for client_id in clients_to_setup:
			self.productOnClient_updateObjects(
				ProductOnClient(productId=product_id, productType=product_type, clientId=client_id, actionRequest="setup")
			)

		return clients_to_setup

	@rpc_method(deprecated=True, check_acl=False)
	def setupWhereFailed(self: BackendProtocol, productId: str) -> set[str]:  # pylint: disable=invalid-name
		"""
		Set the product with the id `productId` to 'setup' on every client
		where the action result is 'failed'.

		The action request will only be set if the depot the client is assigend
		to has a product installed where 'setup' can be set.

		:return: the ID of all clients that have been processed.
		:rtype: set
		"""
		product_id = forceProductId(productId)

		products = self.product_getObjects(id=product_id)
		if not products:
			raise BackendMissingDataError(f"No product with id {product_id!r}")

		clients_with_failed_product = set(
			poc.clientId for poc in self.productOnClient_getObjects(productId=product_id, actionResult="failed")
		)
		if not clients_with_failed_product:
			logger.notice('No clients have %s with installation status "failed".', product_id)
			return set()

		depot_to_clients = defaultdict(set)
		for client_to_depot in self.configState_getClientToDepotserver():
			depot_to_clients[client_to_depot["depotId"]].add(client_to_depot["clientId"])

		product_type = None
		clients_to_setup = set()
		for product in products:
			product_type = product.getType()

			logger.debug("Processing %s...", product)
			if product.getSetupScript():
				pods = self.productOnDepot_getObjects(
					productId=product.id, productVersion=product.productVersion, packageVersion=product.packageVersion
				)

				for depot in (pod.depotId for pod in pods):
					for client_id in (c for c in depot_to_clients[depot] if c in clients_with_failed_product):
						clients_to_setup.add(client_id)

		assert product_type
		logger.debug("Clients to 'setup': %s", clients_to_setup)
		for client_id in clients_to_setup:
			self.productOnClient_updateObjects(
				ProductOnClient(productId=product_id, productType=product_type, clientId=client_id, actionRequest="setup")
			)

		return clients_to_setup
