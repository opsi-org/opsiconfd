# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.product_on_client
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import ProductOnClient
from opsicommon.types import forceObjectClass, forceObjectClassList

from opsiconfd.check.cache import clear_check_cache
from opsiconfd.config import config

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductOnClientMixin(Protocol):
	def productOnClient_bulkInsertObjects(self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient]) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_ON_CLIENT", objs=productOnClients)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def productOnClient_insertObject(self: BackendProtocol, productOnClient: dict | ProductOnClient) -> None:
		ace = self._get_ace("productOnClient_insertObject")
		productOnClient = forceObjectClass(productOnClient, ProductOnClient)
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True)
		if not self.events_enabled:
			return
		data = {
			"productId": productOnClient.productId,
			"productType": productOnClient.productType,
			"clientId": productOnClient.clientId,
			"installationStatus": productOnClient.installationStatus,
			"actionRequest": productOnClient.actionRequest,
		}
		self._send_messagebus_event("productOnClient_created", data=data)
		self.opsipxeconfd_product_on_clients_updated(productOnClient)

	@rpc_method(check_acl=False)
	def productOnClient_updateObject(self: BackendProtocol, productOnClient: dict | ProductOnClient) -> None:
		ace = self._get_ace("productOnClient_updateObject")
		productOnClient = forceObjectClass(productOnClient, ProductOnClient)
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=False, set_null=False)
		if not self.events_enabled:
			return
		data = {
			"productId": productOnClient.productId,
			"productType": productOnClient.productType,
			"clientId": productOnClient.clientId,
			"installationStatus": productOnClient.installationStatus,
			"actionRequest": productOnClient.actionRequest,
		}
		self._send_messagebus_event("productOnClient_updated", data=data)
		self.opsipxeconfd_product_on_clients_updated(productOnClient)

	@clear_check_cache(check_id="products_on_clients")
	@rpc_method(check_acl=False)
	def productOnClient_createObjects(
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_createObjects")
		productOnClients = forceObjectClassList(productOnClients, ProductOnClient)
		with self._mysql.session() as session:
			for productOnClient in productOnClients:
				self._mysql.insert_object(
					table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True, session=session
				)
		if not self.events_enabled:
			return
		for productOnClient in productOnClients:
			data = {
				"productId": productOnClient.productId,
				"productType": productOnClient.productType,
				"clientId": productOnClient.clientId,
				"installationStatus": productOnClient.installationStatus,
				"actionRequest": productOnClient.actionRequest,
			}
			self._send_messagebus_event("productOnClient_created", data=data)
		self.opsipxeconfd_product_on_clients_updated(productOnClients)

	@clear_check_cache(check_id="products_on_clients")
	@rpc_method(check_acl=False)
	def productOnClient_updateObjects(
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_updateObjects")
		productOnClients = forceObjectClassList(productOnClients, ProductOnClient)
		with self._mysql.session() as session:
			for productOnClient in productOnClients:
				self._mysql.insert_object(
					table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=False, session=session
				)
		if not self.events_enabled:
			return
		for productOnClient in productOnClients:
			data = {
				"productId": productOnClient.productId,
				"productType": productOnClient.productType,
				"clientId": productOnClient.clientId,
				"installationStatus": productOnClient.installationStatus,
				"actionRequest": productOnClient.actionRequest,
			}
			self._send_messagebus_event("productOnClient_updated", data=data)
		self.opsipxeconfd_product_on_clients_updated(productOnClients)

	@rpc_method(check_acl=False)
	def productOnClient_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[ProductOnClient]:
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", ace=ace, object_type=ProductOnClient, attributes=attributes, filter=filter
		)

	@rpc_method(deprecated=True, alternative_method="productOnClient_getObjects", check_acl=False)
	def productOnClient_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productOnClient_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_idents(table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, ace=ace, ident_type=returnType, filter=filter)

	@clear_check_cache(check_id="products_on_clients")
	@rpc_method(check_acl=False)
	def productOnClient_deleteObjects(
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		if not productOnClients:
			return
		ace = self._get_ace("productOnClient_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, obj=productOnClients, ace=ace)
		if not self.events_enabled:
			return
		productOnClients = forceObjectClassList(productOnClients, ProductOnClient)
		for productOnClient in productOnClients:
			data = {
				"productId": productOnClient.productId,
				"productType": productOnClient.productType,
				"clientId": productOnClient.clientId,
				"installationStatus": productOnClient.installationStatus,
				"actionRequest": productOnClient.actionRequest,
			}
			self._send_messagebus_event("productOnClient_deleted", data=data)
		self.opsipxeconfd_product_on_clients_deleted(productOnClients)

	@rpc_method(check_acl=False)
	def productOnClient_create(
		self: BackendProtocol,
		productId: str,
		productType: str,
		clientId: str,
		installationStatus: str | None = None,
		actionRequest: str | None = None,
		lastAction: str | None = None,
		actionProgress: str | None = None,
		actionResult: str | None = None,
		productVersion: str | None = None,
		packageVersion: str | None = None,
		modificationTime: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productOnClient_createObjects(ProductOnClient.fromHash(_hash))

	@rpc_method(check_acl=False)
	def productOnClient_delete(
		self: BackendProtocol, productId: list[str] | str, clientId: list[str] | str, productType: list[str] | str | None = None
	) -> None:
		if productType is None:
			productType = []
		idents = self.productOnClient_getIdents(returnType="dict", productId=productId, productType=productType, clientId=clientId)
		if idents:
			self.productOnClient_deleteObjects(idents)

	@rpc_method(check_acl=False)
	def productOnClient_updateObjectsWithDependencies(
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> list[ProductOnClient]:
		"""
		Like productOnClient_updateObjects, but add dependent product actions.
		"""
		product_on_clients = self.productOnClient_addDependencies(productOnClients)
		self.productOnClient_updateObjects(product_on_clients)
		return product_on_clients

	@rpc_method(check_acl=False)
	def productOnClient_getObjectsWithSequence(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[ProductOnClient]:
		"""
		Like productOnClient_getObjects, but return objects in order and with attribute actionSequence set.
		Will not add dependent ProductOnClients!
		If attributes are passed and `actionSequence` is not included in the list of attributes,
		the method behaves like `productOnClient_getObjects` (which is faster).
		"""
		if attributes and "actionSequence" not in attributes:
			return self.productOnClient_getObjects(attributes, **filter)

		ace = self._get_ace("productOnClient_getObjects")
		product_on_clients = self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", ace=ace, object_type=ProductOnClient, attributes=attributes, filter=filter
		)
		action_requests = {(poc.clientId, poc.productId): poc.actionRequest for poc in product_on_clients}

		ret_product_on_clients = []
		debug_log = "poc_seq" if "prod-dep-log" in config.debug_options else None
		for groups in self.get_product_action_groups(product_on_clients, debug_log=debug_log).values():
			for idx, group in enumerate(groups):
				for poc in group.product_on_clients:
					if action_request := action_requests.get((poc.clientId, poc.productId)):
						setattr(poc, "actionGroup", idx + 1)
						# Keep actionRequest from database
						poc.actionRequest = action_request or "none"
						if poc.actionRequest == "none":
							poc.actionSequence = -1
						ret_product_on_clients.append(poc)

		return ret_product_on_clients

	@rpc_method(check_acl=False)
	def productOnClient_generateSequence(self: BackendProtocol, productOnClients: list[ProductOnClient]) -> list[ProductOnClient]:
		"""
		Takes a list of ProductOnClient objects.
		Returns the same list of in the order in which the actions must be processed.
		Please also check if `productOnClient_addDependencies` is more suitable.
		"""
		product_ids_by_client_id: dict[str, list[str]] = defaultdict(list)
		for poc in productOnClients:
			product_ids_by_client_id[poc.clientId].append(poc.productId)

		return [
			poc
			for group in self.get_product_action_groups(productOnClients).values()
			for g in group
			for poc in g.product_on_clients
			if poc.productId in product_ids_by_client_id.get(poc.clientId, [])
		]

	@rpc_method()
	def productOnClient_addDependencies(self: BackendProtocol, productOnClients: list[ProductOnClient]) -> list[ProductOnClient]:
		"""
		Takes a list of ProductOnClient objects.
		Adds ProductOnClient objects that are needed to fulfill the ProductDependencies.
		Other ProductOnClient objects are read from the backend to check if dependencies are already fulfilled.
		Returns the expanded list of ProductOnClient objects in the order in which the actions must be processed
		(like productOnClient_generateSequence would do).
		"""
		return [poc for group in self.get_product_action_groups(productOnClients).values() for g in group for poc in g.product_on_clients]

	@rpc_method(check_acl=False)
	def productOnClient_getActionGroups(self: BackendProtocol, clientId: str) -> list[dict]:
		"""
		Get product action groups of action requests set for a client.
		"""
		ace = self._get_ace("productOnClient_getObjects")
		product_on_clients = self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", ace=ace, object_type=ProductOnClient, filter={"clientId": clientId}
		)

		action_groups: list[dict] = []
		for group in self.get_product_action_groups(product_on_clients).get(clientId, []):
			group.product_on_clients = [
				poc.to_hash()  # type: ignore[misc]
				for poc in group.product_on_clients
				if poc.actionRequest and poc.actionRequest != "none"
			]
			if group.product_on_clients:
				group.dependencies = {
					product_id: [d.to_hash() for d in dep]  # type: ignore[misc]
					for product_id, dep in group.dependencies.items()
				}
				action_groups.append(group)  # type: ignore[arg-type]

		return action_groups
