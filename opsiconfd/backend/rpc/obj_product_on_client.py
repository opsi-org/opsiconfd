# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_on_client
"""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Callable, Protocol

from opsicommon.exceptions import BackendMissingDataError
from opsicommon.objects import Product, ProductDependency, ProductOnClient
from opsicommon.types import forceObjectClass, forceObjectClassList

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductOnClientMixin(Protocol):
	def productOnClient_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient]
	) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_ON_CLIENT", objs=productOnClients)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def productOnClient_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClient: dict | ProductOnClient
	) -> None:
		self._check_module("mysql_backend")
		ace = self._get_ace("productOnClient_insertObject")
		productOnClient = forceObjectClass(productOnClient, ProductOnClient)
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True)
		if not self.events_enabled:
			return
		self.opsipxeconfd_product_on_clients_updated(productOnClient)
		self._send_messagebus_event("productOnClient_created", data=productOnClient.getIdent("dict"))  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def productOnClient_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClient: dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_updateObject")
		productOnClient = forceObjectClass(productOnClient, ProductOnClient)
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=False, set_null=False)
		if not self.events_enabled:
			return
		self.opsipxeconfd_product_on_clients_updated(productOnClient)
		self._send_messagebus_event("productOnClient_updated", data=productOnClient.getIdent("dict"))  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def productOnClient_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		self._check_module("mysql_backend")
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
			self._send_messagebus_event("productOnClient_created", data=productOnClient.getIdent("dict"))  # type: ignore[arg-type]
		self.opsipxeconfd_product_on_clients_updated(productOnClients)

	@rpc_method(check_acl=False)
	def productOnClient_updateObjects(  # pylint: disable=invalid-name
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
			self._send_messagebus_event("productOnClient_updated", data=productOnClient.getIdent("dict"))  # type: ignore[arg-type]
		self.opsipxeconfd_product_on_clients_updated(productOnClients)

	@rpc_method(check_acl=False)
	def productOnClient_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[ProductOnClient]:
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", ace=ace, object_type=ProductOnClient, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productOnClient_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productOnClient_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_idents(table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def productOnClient_deleteObjects(  # pylint: disable=invalid-name
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
			self._send_messagebus_event("productOnClient_deleted", data=productOnClient.getIdent("dict"))  # type: ignore[arg-type]
		self.opsipxeconfd_product_on_clients_deleted(productOnClients)

	@rpc_method(check_acl=False)
	def productOnClient_create(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		productId: str,  # pylint: disable=unused-argument
		productType: str,  # pylint: disable=unused-argument
		clientId: str,  # pylint: disable=unused-argument
		installationStatus: str | None = None,  # pylint: disable=unused-argument
		actionRequest: str | None = None,  # pylint: disable=unused-argument
		lastAction: str | None = None,  # pylint: disable=unused-argument
		actionProgress: str | None = None,  # pylint: disable=unused-argument
		actionResult: str | None = None,  # pylint: disable=unused-argument
		productVersion: str | None = None,  # pylint: disable=unused-argument
		packageVersion: str | None = None,  # pylint: disable=unused-argument
		modificationTime: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productOnClient_createObjects(ProductOnClient.fromHash(_hash))

	@rpc_method(check_acl=False)
	def productOnClient_delete(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: list[str] | str, clientId: list[str] | str, productType: list[str] | str | None = None
	) -> None:
		if productType is None:
			productType = []
		idents = self.productOnClient_getIdents(returnType="dict", productId=productId, productType=productType, clientId=clientId)
		if idents:
			self.productOnClient_deleteObjects(idents)

	@rpc_method(check_acl=False)
	def productOnClient_updateObjectsWithDependencies(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		"""
		Like productOnClient_updateObjects, but add dependent product actions.
		"""
		productOnClients = self.productOnClient_addDependencies(productOnClients)
		self.productOnClient_updateObjects(productOnClients)

	@rpc_method(check_acl=False)
	def productOnClient_getObjectsWithSequence(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[ProductOnClient]:
		"""
		Like productOnClient_getObjects, but return objects in order and with attribute actionSequence set.
		Will not add dependent ProductOnClients!
		"""
		ace = self._get_ace("productOnClient_getObjects")
		product_on_clients = self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", ace=ace, object_type=ProductOnClient, attributes=attributes, filter=filter
		)
		action_requests = {f"{poc.clientId}:{poc.productId}": poc.actionRequest for poc in product_on_clients}
		product_on_clients = self.productOnClient_generateSequence(product_on_clients)
		for poc in product_on_clients:
			if action_request := action_requests.get(f"{poc.clientId}:{poc.productId}"):
				poc.actionRequest = action_request
				if not poc.actionRequest or poc.actionRequest == "none":
					poc.actionSequence = -1
		return product_on_clients

	@rpc_method(check_acl=False)
	def productOnClient_generateSequence(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: list[ProductOnClient]
	) -> list[ProductOnClient]:
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

	@rpc_method(check_acl=False)
	def productOnClient_addDependencies(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: list[ProductOnClient]
	) -> list[ProductOnClient]:
		"""
		Takes a list of ProductOnClient objects.
		Adds ProductOnClient objects that are needed to fulfill the ProductDependencies.
		Other ProductOnClient objects are read from the backend to check if dependencies are already fulfilled.
		Returns the expanded list of ProductOnClient objects in the order in which the actions must be processed
		(like productOnClient_generateSequence would do).
		"""
		return [poc for group in self.get_product_action_groups(productOnClients).values() for g in group for poc in g.product_on_clients]
