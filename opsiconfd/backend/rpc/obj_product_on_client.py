# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.product_on_client
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Protocol

from opsi.opsi.service.model.object import AuditLog, AuditLogEventType, AuditLogProductActionRequest, ProductOnClient
from opsi.opsi.service.model.type import to_list, to_object_class, to_object_class_list

from opsiconfd import contextvar_client_session
from opsiconfd.audit_log import audit_log_event_enabled
from opsiconfd.config import config
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductOnClientMixin(Protocol):
	def _productOnClient_action_request_supplied(self: BackendProtocol, productOnClient: dict | ProductOnClient) -> bool:
		if isinstance(productOnClient, dict):
			return productOnClient.get("actionRequest") is not None
		return productOnClient.actionRequest is not None

	def _productOnClient_to_objects_with_action_request_audit_candidates(
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> tuple[list[ProductOnClient], list[ProductOnClient]]:
		raw_product_on_clients = to_list(productOnClients)
		action_request_supplied = [
			self._productOnClient_action_request_supplied(product_on_client) for product_on_client in raw_product_on_clients
		]
		product_on_clients = to_object_class_list(raw_product_on_clients, ProductOnClient)
		return product_on_clients, [poc for poc, supplied in zip(product_on_clients, action_request_supplied) if supplied]

	def _productOnClient_audit_action_request_set(self: BackendProtocol, productOnClients: list[ProductOnClient]) -> None:
		if not productOnClients or not audit_log_event_enabled(AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST):
			return

		session = contextvar_client_session.get()
		username = session.username if session else None
		audit_logs = [
			AuditLog(
				eventType=AuditLogEventType.CLIENT_PRODUCT_ACTION_REQUEST,
				username=username,
				actorType=session.user_type if session else None,
				actorId=username,
				clientAddress=session.client_addr if session else None,
				userAgent=session.user_agent if session and session.user_agent else None,
				hostId=product_on_client.clientId,
				message=f"Action request {(product_on_client.actionRequest or 'none')!r} set for product {product_on_client.productId!r} on client {product_on_client.clientId!r}",
				productActionRequest=AuditLogProductActionRequest(
					productId=product_on_client.productId,
					actionRequest=product_on_client.actionRequest or "none",
				),
			)
			for product_on_client in productOnClients
		]
		try:
			self.auditLog_bulkInsertObjects(audit_logs)
		except Exception as err:
			logger.error("Failed to write ProductOnClient actionRequest audit log: %s", err, exc_info=True)

	def productOnClient_bulkInsertObjects(self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient]) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_ON_CLIENT", objs=productOnClients)  # ty: ignore[invalid-argument-type]

	@rpc_method(check_acl=False)
	def productOnClient_insertObject(self: BackendProtocol, productOnClient: dict | ProductOnClient) -> None:
		ace = self._get_ace("productOnClient_insertObject")
		productOnClient = to_object_class(productOnClient, ProductOnClient)
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True)

		if not self.events_enabled:
			return

		if self._productOnClient_action_request_supplied(productOnClient):
			self._productOnClient_audit_action_request_set([productOnClient])

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
		productOnClient = to_object_class(productOnClient, ProductOnClient)
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=False, set_null=False)

		if not self.events_enabled:
			return

		if self._productOnClient_action_request_supplied(productOnClient):
			self._productOnClient_audit_action_request_set([productOnClient])

		data = {
			"productId": productOnClient.productId,
			"productType": productOnClient.productType,
			"clientId": productOnClient.clientId,
			"installationStatus": productOnClient.installationStatus,
			"actionRequest": productOnClient.actionRequest,
			"actionResult": productOnClient.actionResult,
		}
		self._send_messagebus_event("productOnClient_updated", data=data)
		self.opsipxeconfd_product_on_clients_updated(productOnClient)

	@rpc_method(check_acl=False)
	def productOnClient_createObjects(
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_createObjects")
		productOnClients, audit_candidates = self._productOnClient_to_objects_with_action_request_audit_candidates(productOnClients)
		with self._mysql.session() as session:
			for productOnClient in productOnClients:
				self._mysql.insert_object(
					table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True, session=session
				)

		if not self.events_enabled:
			return

		if audit_candidates:
			self._productOnClient_audit_action_request_set(audit_candidates)

		for productOnClient in productOnClients:
			data = {
				"productId": productOnClient.productId,
				"productType": productOnClient.productType,
				"clientId": productOnClient.clientId,
				"installationStatus": productOnClient.installationStatus,
				"actionRequest": productOnClient.actionRequest,
				"actionResult": productOnClient.actionResult,
			}
			self._send_messagebus_event("productOnClient_created", data=data)
		self.opsipxeconfd_product_on_clients_updated(productOnClients)

	@rpc_method(check_acl=False)
	def productOnClient_updateObjects(
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_updateObjects")
		productOnClients, audit_candidates = self._productOnClient_to_objects_with_action_request_audit_candidates(productOnClients)
		with self._mysql.session() as session:
			for productOnClient in productOnClients:
				self._mysql.insert_object(
					table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=False, session=session
				)

		if not self.events_enabled:
			return

		if audit_candidates:
			self._productOnClient_audit_action_request_set(audit_candidates)

		for productOnClient in productOnClients:
			data = {
				"productId": productOnClient.productId,
				"productType": productOnClient.productType,
				"clientId": productOnClient.clientId,
				"installationStatus": productOnClient.installationStatus,
				"actionRequest": productOnClient.actionRequest,
				"actionResult": productOnClient.actionResult,
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

		productOnClients = to_object_class_list(productOnClients, ProductOnClient)

		for productOnClient in productOnClients:
			data = {
				"productId": productOnClient.productId,
				"productType": productOnClient.productType,
				"clientId": productOnClient.clientId,
				"installationStatus": productOnClient.installationStatus,
				"actionRequest": productOnClient.actionRequest,
				"actionResult": productOnClient.actionResult,
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
						setattr(poc, "actionGroupPriority", group.priority)
						setattr(poc, "actionPriority", group.priorities[poc.productId])
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
			group.product_on_clients = [  # ty: ignore[invalid-assignment]
				poc.to_hash() for poc in group.product_on_clients if poc.actionRequest and poc.actionRequest != "none"
			]
			if group.product_on_clients:
				group.dependencies = {  # ty: ignore[invalid-assignment]
					product_id: [d.to_hash() for d in dep] for product_id, dep in group.dependencies.items()
				}
				action_groups.append(group)  # ty: ignore[invalid-argument-type]

		return action_groups
