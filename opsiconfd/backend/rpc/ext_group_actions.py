# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
rpc methods wim
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import BackendMissingDataError

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtGroupActionsMixin(Protocol):
	def _get_clients_on_depot_by_host_group(self: BackendProtocol, host_group_id: str) -> dict[str, list[str]]:
		clients_in_group = self._get_clients_in_host_group(host_group_id)
		logger.debug("Group %s has the following clients: %s", host_group_id, clients_in_group)
		depots_with_clients = self._get_clients_on_depots(clients_in_group)
		logger.debug("The clients are using the following depots: %s", depots_with_clients)
		return depots_with_clients

	def _get_clients_in_host_group(self: BackendProtocol, host_group_id: str) -> list[str]:
		return [c.objectId for c in self.objectToGroup_getObjects(groupId=host_group_id, groupType="HostGroup")]

	def _get_clients_on_depots(self: BackendProtocol, client_ids: list[str]) -> dict[str, list[str]]:
		"""Returns a dict where the depot is the key and the value a list of clients."""
		clients_on_depot: dict[str, list[str]] = {}

		for depot_client_hash in self.configState_getClientToDepotserver(clientIds=client_ids):
			if depot_client_hash["depotId"] not in clients_on_depot:
				clients_on_depot[depot_client_hash["depotId"]] = []
			clients_on_depot[depot_client_hash["depotId"]].append(depot_client_hash["clientId"])

		logger.debug("Found the following clients on depots: %s", clients_on_depot)
		return clients_on_depot

	def _is_product_on_depot(self: BackendProtocol, product_id: str, depot_id: str) -> bool:
		return bool(self.productOnDepot_getObjects(productId=product_id, depotId=depot_id))

	def _update_action_request_on_clients(self: BackendProtocol, clients: list[str], product_id: str, action_request: str) -> None:
		product_on_clients = self.productOnClient_getObjects(clientId=clients, productId=product_id)
		not_updated_clients = set(clients)

		for poc in product_on_clients:
			poc.setActionRequest(action_request)
			not_updated_clients.remove(poc.clientId)
			logger.debug('ActionRequest "%s" was set on client "%s".', action_request, poc.clientId)

		self.productOnClient_updateObjects(product_on_clients)

		if not_updated_clients:
			product_type = self.product_getObjects(id=product_id)[0].getType()
			for client in not_updated_clients:
				self.productOnClient_create(product_id, product_type, client, actionRequest=action_request)

	@rpc_method(deprecated=True, check_acl=False)
	def setProductActionRequestForHostGroup(self: BackendProtocol, hostGroupId: str, productId: str, actionRequest: str) -> None:
		depots_with_clients = self._get_clients_on_depot_by_host_group(hostGroupId)
		for depot_id, client_ids in depots_with_clients.items():
			if not self._is_product_on_depot(productId, depot_id):
				raise BackendMissingDataError(f"Product {productId!r} not found on depot server {depot_id!r}")

			self._update_action_request_on_clients(client_ids, productId, actionRequest)

	@rpc_method(deprecated=True, check_acl=False)
	def setProductActionRequestForProductGroup(self: BackendProtocol, hostGroupId: str, productGroupId: str, actionRequest: str) -> None:
		depots_with_clients = self._get_clients_on_depot_by_host_group(hostGroupId)

		for product_group_mapping in self.objectToGroup_getObjects(groupType="ProductGroup", groupId=productGroupId):
			product_id = product_group_mapping.objectId
			for depot_id, client_ids in depots_with_clients.items():
				if not self._is_product_on_depot(product_id, depot_id):
					raise BackendMissingDataError(f"Product {product_id!r} not found on depot server {depot_id}")
				self._update_action_request_on_clients(client_ids, product_id, actionRequest)

	@rpc_method(deprecated=True, check_acl=False)
	def setProductPropertyForHostGroup(self: BackendProtocol, productId: str, propertyId: str, propertyValue: Any, groupId: str) -> None:
		clients_in_group = [c.objectId for c in self.objectToGroup_getObjects(groupId=groupId, groupType="HostGroup")]
		product_property_states = self.productPropertyState_getObjects(
			objectId=clients_in_group, productId=productId, propertyId=propertyId
		)
		clients_without_property = set(clients_in_group)

		for product_property_state in product_property_states:
			product_property_state.setValues(propertyValue)
			clients_without_property.remove(product_property_state.objectId)

		self.productPropertyState_updateObjects(product_property_states)

		for client in clients_without_property:
			self.productPropertyState_create(productId, propertyId, client, values=propertyValue)

	@rpc_method(deprecated=True, check_acl=False)
	def getPossibleImagefileValuesForHostGroup(self: BackendProtocol, groupId: str) -> list[str]:
		def add_client_to_product(client_id: str, product_id: str) -> None:
			if product_id not in products_with_clients:
				products_with_clients[product_id] = set()
			products_with_clients[product_id].add(client_id)

		product_id = "opsi-local-image-restore"
		property_id = "imagefiles_list"

		clients_in_group = self._get_clients_in_host_group(groupId)
		product_property_states = self.productPropertyState_getObjects(
			objectId=clients_in_group, productId=product_id, propertyId=property_id
		)

		products_with_clients: dict[str, set[str]] = {}
		for product_property_state in product_property_states:
			for key in product_property_state.values:
				if "," in key:
					# This is the workaround for a bug where the list of
					# images will become a comma-seperated string instead of
					# a list of strings.
					for key_part in key.split(","):
						add_client_to_product(product_property_state.objectId, key_part)
				else:
					add_client_to_product(product_property_state.objectId, key)

		client_set = set(clients_in_group)
		return [product for product, clients in products_with_clients.items() if client_set == clients]

	@rpc_method(deprecated=True, check_acl=False)
	def groupname_exists(self: BackendProtocol, groupId: str) -> bool:
		return bool(self.group_getObjects(id=groupId))

	@rpc_method(deprecated=True, check_acl=False)
	def group_rename(self: BackendProtocol, oldGroupId: str, newGroupId: str) -> None:
		if self.groupname_exists(newGroupId):
			raise ValueError(f"Group {newGroupId!r} already exists")

		if not self.groupname_exists(oldGroupId):
			raise BackendMissingDataError(f"Old group {oldGroupId!r} does not exist")

		old_group = self.group_getObjects(id=oldGroupId)[0]
		self.group_createHostGroup(
			id=newGroupId, description=old_group.description, notes=old_group.notes, parentGroupId=old_group.parentGroupId
		)

		for group in self.group_getObjects(parentGroupId=oldGroupId):
			group.parentGroupId = newGroupId
			self.group_updateObject(group)

		for old_obj_to_grp in self.objectToGroup_getObjects(groupId=oldGroupId):
			self.objectToGroup_create(groupType=old_obj_to_grp.groupType, groupId=newGroupId, objectId=old_obj_to_grp.objectId)
			self.objectToGroup_delete(groupType=old_obj_to_grp.groupType, groupId=oldGroupId, objectId=old_obj_to_grp.objectId)

		self.group_delete(id=oldGroupId)
