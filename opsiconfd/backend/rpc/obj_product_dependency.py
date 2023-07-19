# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_dependency
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import OpsiError
from opsicommon.logging.constants import TRACE  # type: ignore[import]
from opsicommon.objects import (  # type: ignore[import]
	LocalbootProduct,
	Product,
	ProductDependency,
	ProductOnClient,
	ProductOnDepot,
)
from opsicommon.types import (  # type: ignore[import]
	forceList,
	forceObjectClass,
)

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class OpsiProductNotAvailableError(OpsiError):
	ExceptionShortDescription = "Product not available on depot"


class OpsiProductNotAvailableOnDepotError(OpsiError):
	ExceptionShortDescription = "Product not available on depot"


@dataclass
class ProductActionGroup:
	priority: int = 0
	product_on_clients: list[ProductOnClient] = field(default_factory=list)

	def log(self, level: int = TRACE) -> None:
		if not logger.isEnabledFor(level):
			return
		logger.log(level, "=> Product action group (prio %r)", self.priority)
		for product_on_clients in self.product_on_clients:
			logger.log(level, "   -> %s: %s", product_on_clients.productId, product_on_clients.actionRequest)


class RPCProductDependencyMixin(Protocol):
	def get_product_action_groups(  # pylint: disable=too-many-locals,too-many-statements,too-many-branches
		self: BackendProtocol, product_on_clients: list[ProductOnClient], *, ignore_unavailable_products: bool = True
	) -> dict[str, list[ProductActionGroup]]:
		product_cache: dict[tuple[str, str, str], Product] = {}
		product_on_depot_cache: dict[tuple[str, str], ProductOnDepot] = {}
		product_on_client_cache: dict[tuple[str, str], ProductOnClient] = {}
		product_dependency_cache: dict[tuple[str, str, str], list[ProductDependency]] = {}
		product_on_clients_by_client_id: dict[str, list[ProductOnClient]] = defaultdict(list)
		for poc in product_on_clients:
			product_on_clients_by_client_id[poc.clientId].append(poc)
		client_ids = list(product_on_clients_by_client_id)
		client_to_depot = {c2d["clientId"]: c2d["depotId"] for c2d in self.configState_getClientToDepotserver(clientIds=client_ids)}
		product_action_groups: dict[str, list[ProductActionGroup]] = {c: [] for c in client_ids}

		def get_product(product_id: str, product_version: str, package_version: str) -> Product:
			pkey = (product_id, product_version, package_version)
			if pkey not in product_cache:
				objs = self.product_getObjects(
					id=product_id,
					productVersion=product_version,
					packageVersion=package_version,
				)
				if not objs:
					raise OpsiProductNotAvailableError(f"Product {product_id!r} (version: {product_version}-{package_version}) not found")
				product_cache[pkey] = objs[0]
			return product_cache[pkey]

		def get_product_on_depot(
			depot_id: str, product_id: str, product_version: str | None = None, package_version: str | None = None
		) -> ProductOnDepot:
			pkey = (depot_id, product_id)
			if pkey not in product_on_depot_cache:
				objs = self.productOnDepot_getObjects(
					productId=product_id, productVersion=product_version, packageVersion=package_version, depotId=depot_id
				)
				if not objs:
					raise OpsiProductNotAvailableOnDepotError(
						f"Product {product_id!r} (version: {product_version}-{package_version}) not found on depot {depot_id}"
					)
				product_on_depot_cache[pkey] = objs[0]
			return product_on_depot_cache[pkey]

		def get_product_dependencies(product_id: str, product_version: str, package_version: str) -> list[ProductDependency]:
			pkey = (product_id, product_version, package_version)
			if pkey not in product_dependency_cache:
				objs = self.productDependency_getObjects(
					productId=product_id, productVersion=product_version, packageVersion=package_version
				)
				product_dependency_cache[pkey] = objs
			return product_dependency_cache[pkey]

		def get_product_on_client(product_id: str, product_type: str, client_id: str) -> ProductOnClient:
			pkey = (client_id, product_id)
			if pkey not in product_on_client_cache:
				for poc in product_on_clients_by_client_id.get(client_id, []):
					if poc.productId == product_id:
						product_on_client_cache[pkey] = poc
						break
			if pkey not in product_on_client_cache:
				objs = self.productOnClient_getObjects(productId=product_id, clientId=client_id)
				if not objs:
					poc = ProductOnClient(productId=product_id, productType=product_type, clientId=client_id)
					poc.setDefaults()
					objs = [poc]
				product_on_client_cache[pkey] = objs[0]
			return product_on_client_cache[pkey]

		@dataclass
		class ActionSorter:
			client_id: str
			depot_id: str
			groups: list[DependencyGroup] = field(default_factory=list)
			unsorted_actions: dict[str, list[Action]] = field(default_factory=dict)
			dependencies: dict[str, set[str]] = field(default_factory=dict)

			def add_action_unsorted(self, action: Action) -> None:
				if action.product_id not in self.unsorted_actions:
					self.unsorted_actions[action.product_id] = []
				if action in self.unsorted_actions[action.product_id]:
					return
				self.unsorted_actions[action.product_id].append(action)

			def add_dependency_actions_unsorted(  # pylint: disable=too-many-arguments,too-many-branches
				self,
				action: Action,
				dependency_path: list[str] | None = None,
			) -> None:
				dependency_path = dependency_path or []
				dependency_path.append(action.product_id)
				try:
					product_on_depot = get_product_on_depot(depot_id=self.depot_id, product_id=action.product_id)
					product = get_product(
						product_id=action.product_id,
						product_version=product_on_depot.productVersion,
						package_version=product_on_depot.packageVersion,
					)
				except (OpsiProductNotAvailableError, OpsiProductNotAvailableOnDepotError) as err:
					if not ignore_unavailable_products:
						raise
					logger.info(err)
					return

				for dependency in get_product_dependencies(
					product_id=product.id,
					product_version=product.productVersion,
					package_version=product.packageVersion,
				):
					if dependency.productAction != action.action or dependency.requiredProductId in dependency_path:
						continue

					try:
						dep_product_on_depot = get_product_on_depot(
							depot_id=self.depot_id,
							product_id=dependency.requiredProductId,
							product_version=dependency.requiredProductVersion,
							package_version=dependency.requiredPackageVersion,
						)
						dep_product = get_product(
							product_id=dependency.requiredProductId,
							product_version=dep_product_on_depot.productVersion,
							package_version=dep_product_on_depot.packageVersion,
						)
					except (OpsiProductNotAvailableError, OpsiProductNotAvailableOnDepotError) as err:
						if not ignore_unavailable_products:
							raise
						logger.info(err)
						continue

					dep_poc = get_product_on_client(product_id=dep_product.id, product_type=dep_product.getType(), client_id=client_id)
					required_action = dependency.requiredAction
					if not required_action:
						if (  # pylint: disable=too-many-boolean-expressions
							dependency.requiredInstallationStatus == dep_poc.installationStatus
							and (
								not dependency.requiredProductVersion
								or not dep_poc.productVersion
								or dependency.requiredProductVersion == dep_poc.productVersion
							)
							and (
								not dependency.requiredPackageVersion
								or not dep_poc.packageVersion
								or dependency.requiredPackageVersion == dep_poc.packageVersion
							)
						):
							# Fulfilled
							continue
						if dependency.requiredInstallationStatus == "installed":
							required_action = "setup"
						elif dependency.requiredInstallationStatus == "not_installed":
							required_action = "uninstall"
						else:
							raise ValueError(f"Invalid requiredInstallationStatus: '{dependency.requiredInstallationStatus}'")

					assert required_action

					dep_action = Action(
						product_id=dep_product.id,
						product_type=dep_product.getType(),
						action=required_action,
						priority=dep_product.priority or 0,
						required_by=product.id,
						requirement_type=dependency.requirementType,
					)
					self.add_action_unsorted(dep_action)

					if dependency.requirementType:
						# Only "hard" requirements should end in the same DependencyGroup
						if action.product_id not in self.dependencies:
							self.dependencies[action.product_id] = set()
						self.dependencies[action.product_id].add(dep_action.product_id)

						if dep_action.product_id not in self.dependencies:
							self.dependencies[dep_action.product_id] = set()
						self.dependencies[dep_action.product_id].add(action.product_id)

					self.add_dependency_actions_unsorted(
						action=dep_action,
						dependency_path=dependency_path,
					)

			def add_action(self, dependency_group: DependencyGroup, action: Action) -> None:
				dependency_group.add_action(action)
				self.add_dependency_actions(dependency_group, action)

			def add_dependency_actions(self, dependency_group: DependencyGroup, action: Action) -> None:
				for dep_product_id in self.dependencies.get(action.product_id, set()):
					dep_actions = self.unsorted_actions.pop(dep_product_id, [])
					for dep_action in dep_actions:
						self.add_action(dependency_group, dep_action)

			def sort(self) -> None:
				for actions in list(self.unsorted_actions.values()):
					for action in actions:
						self.add_dependency_actions_unsorted(action)

				for product_id in list(self.unsorted_actions):
					actions = self.unsorted_actions.pop(product_id, [])
					if not actions:
						continue

					dependency_group = DependencyGroup()
					self.groups.append(dependency_group)
					for action in actions:
						self.add_action(dependency_group, action)

		@dataclass
		class DependencyGroup:
			"""
			A group of actions with hard dependencies on each other.

			Example:

			- product2 requires product1 before not_installed
			- product3 requires product4 after once

			Action lists
			┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
			│ ActionList              │ │ ActionList              │ │ ActionList              │
			│                         │ │                         │ │                         │
			│  ┌───────────────────┐  │ │  ┌───────────────────┐  │ │  ┌───────────────────┐  │
			│  │priority: 0        │  │ │  │priority: 20       │  │ │  │priority: -90      │  │
			│  │product1: uninstall│  │ │  │product2: setup    │  │ │  │product4: once     │  │
			│  │                   │  │ │  │                   │  │ │  │                   │  │
			│  └───────────────────┘  │ │  └───────────────────┘  │ │  └───────────────────┘  │
			│                         │ │                         │ │                         │
			│                         │ │  ┌───────────────────┐  │ │                         │
			│                         │ │  │priority: 10       │  │ │                         │
			│                         │ │  │product3: setup    │  │ │                         │
			│                         │ │  │                   │  │ │                         │
			│                         │ │  └───────────────────┘  │ │                         │
			│                         │ │                         │ │                         │
			└─────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
			"""

			action_lists: list[ActionList] = field(default_factory=list)

			def log(self, level: int = TRACE) -> None:
				if not logger.isEnabledFor(level):
					return
				logger.log(level, "=> Dependency group (prio %r to %r)", self.min_priority(), self.max_priority())
				for action_list in self.action_lists:
					logger.log(level, "   => Action list")
					for action in action_list.actions:
						logger.log(level, "      -> %s: %s (%r)", action.product_id, action.action, action.priority)

			def add_action(self, action: Action) -> None:
				cur_action_list_index, cur_action_index = self.action_list_idx(action.product_id)
				dep_action_list_index, _ = self.action_list_idx(action.required_by) if action.required_by else (-1, -1)

				if action.requirement_type:
					# Add a new ActionList before or after
					if cur_action_list_index != -1:
						self.action_lists[cur_action_list_index].actions.pop(cur_action_index)
					action_list_index = dep_action_list_index
					if action.requirement_type == "after":
						action_list_index += 1
					self.action_lists.insert(action_list_index, ActionList(actions=[action]))
					if not self.action_lists[cur_action_list_index].actions:
						# Remove empty list
						del self.action_lists[cur_action_list_index]
				else:
					if cur_action_list_index != -1:
						# Keep position
						return
					if not self.action_lists:
						self.action_lists = [ActionList()]
					action_list_index = dep_action_list_index if dep_action_list_index != -1 else len(self.action_lists) - 1
					self.action_lists[action_list_index].add_action(action)

			def action_list_idx(self, product_id: str) -> tuple[int, int]:
				for idx, action_list in enumerate(self.action_lists):
					for idx2, act in enumerate(action_list.actions):
						if act.product_id == product_id:
							return idx, idx2
				return -1, -1

			def min_priority(self) -> int:
				return min(al.actions[0].priority if al and al.actions else 0 for al in self.action_lists)

			def max_priority(self) -> int:
				return max(al.actions[-1].priority if al and al.actions else 0 for al in self.action_lists)

		@dataclass
		class ActionList:
			actions: list[Action] = field(default_factory=list)

			def add_action(self, action: Action) -> None:
				self.actions.append(action)
				self.actions.sort(key=lambda a: a.priority)

		@dataclass
		class Action:
			product_id: str
			product_type: str
			action: str
			priority: int
			required_by: str | None = None
			requirement_type: str | None = None
			product_on_client: ProductOnClient | None = None

			def get_product_on_client(self, client_id: str) -> ProductOnClient:
				product_on_client = (
					self.product_on_client.clone()
					if self.product_on_client
					else ProductOnClient(productId=self.product_id, productType=self.product_type, clientId=client_id)
				)
				product_on_client.actionRequest = self.action
				return product_on_client

		for client_id, pocs in product_on_clients_by_client_id.items():
			product_action_groups[client_id] = []
			depot_id = client_to_depot.get(client_id, client_id)
			action_sorter = ActionSorter(client_id=client_id, depot_id=depot_id)

			for poc in pocs:
				if not poc.actionRequest:
					continue

				logger.debug("add_product_on_client: %s", poc)

				try:
					product_on_depot = get_product_on_depot(depot_id=depot_id, product_id=poc.productId)
					poc.productVersion = product_on_depot.productVersion
					poc.packageVersion = product_on_depot.packageVersion
					product = get_product(
						product_id=poc.productId,
						product_version=poc.productVersion,
						package_version=poc.packageVersion,
					)
				except (OpsiProductNotAvailableError, OpsiProductNotAvailableOnDepotError) as err:
					if not ignore_unavailable_products:
						raise
					logger.info(err)
					continue

				action = Action(
					product_id=poc.productId,
					product_type=product.getType(),
					action=poc.actionRequest,
					priority=product.priority or 0,
					product_on_client=poc,
				)
				action_sorter.add_action_unsorted(action)

			action_sorter.sort()

			for dependency_group in action_sorter.groups:
				from opsicommon.logging.constants import ESSENTIAL

				dependency_group.log(ESSENTIAL)
				group = ProductActionGroup()
				for action_list in dependency_group.action_lists:
					for action in action_list.actions:
						group.product_on_clients.append(action.get_product_on_client(client_id))
				if not group.product_on_clients:
					continue

				min_prio = dependency_group.min_priority()
				max_prio = dependency_group.max_priority()
				if max_prio > 0:
					# Prefer highest priority > 0
					group.priority = max_prio
				elif min_prio < 0:
					# After that prefer lowest priority < 0
					group.priority = min_prio
				product_action_groups[client_id].append(group)

			product_action_groups[client_id].sort(key=lambda x: x.priority, reverse=True)

			action_sequence = 0
			for group in product_action_groups[client_id]:
				group.log()
				for poc in group.product_on_clients:
					poc.actionSequence = action_sequence
					action_sequence += 1

		return product_action_groups

	def productDependency_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependencies: list[dict] | list[ProductDependency]  # pylint: disable=invalid-name
	) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_DEPENDENCY", objs=productDependencies)  # type: ignore[arg-type]

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependency: dict | ProductDependency  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productDependency_insertObject")
		productDependency = forceObjectClass(productDependency, ProductDependency)
		self._mysql.insert_object(table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependency: dict | ProductDependency  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productDependency_updateObject")
		productDependency = forceObjectClass(productDependency, ProductDependency)
		self._mysql.insert_object(table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productDependency_createObjects")
		with self._mysql.session() as session:
			for productDependency in forceList(productDependencies):
				productDependency = forceObjectClass(productDependency, ProductDependency)
				self._mysql.insert_object(
					table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productDependency_updateObjects")
		with self._mysql.session() as session:
			for productDependency in forceList(productDependencies):
				productDependency = forceObjectClass(productDependency, ProductDependency)
				self._mysql.insert_object(
					table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def productDependency_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[ProductDependency]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_DEPENDENCY", ace=ace, object_type=ProductDependency, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productDependency_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_DEPENDENCY", object_type=ProductDependency, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productDependency_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_idents(
			table="PRODUCT_DEPENDENCY", object_type=ProductDependency, ace=ace, ident_type=returnType, filter=filter
		)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency
	) -> None:
		if not productDependencies:
			return
		ace = self._get_ace("productDependency_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_DEPENDENCY", object_type=ProductDependency, obj=productDependencies, ace=ace)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_create(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		productId: str,  # pylint: disable=unused-argument
		productVersion: str,  # pylint: disable=unused-argument
		packageVersion: str,  # pylint: disable=unused-argument
		productAction: str,  # pylint: disable=unused-argument
		requiredProductId: str | None = None,  # pylint: disable=unused-argument
		requiredProductVersion: str | None = None,  # pylint: disable=unused-argument
		requiredPackageVersion: str | None = None,  # pylint: disable=unused-argument
		requiredAction: str | None = None,  # pylint: disable=unused-argument
		requiredInstallationStatus: str | None = None,  # pylint: disable=unused-argument
		requirementType: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productDependency_createObjects(ProductDependency.fromHash(_hash))

	@rpc_method(check_acl=False)
	def productDependency_delete(  # pylint: disable=redefined-builtin,invalid-name,too-many-arguments
		self: BackendProtocol,
		productId: list[str] | str,
		productVersion: list[str] | str,
		packageVersion: list[str] | str,
		productAction: list[str] | str,
		requiredProductId: list[str] | str,
	) -> None:
		idents = self.productDependency_getIdents(
			returnType="dict",
			productId=productId,
			productVersion=productVersion,
			packageVersion=packageVersion,
			productAction=productAction,
			requiredProductId=requiredProductId,
		)
		if idents:
			self.productDependency_deleteObjects(idents)

	@rpc_method(check_acl=False, use_cache="product_ordering")
	def getProductOrdering(  # pylint: disable=invalid-name,too-many-branches
		self: BackendProtocol, depotId: str, sortAlgorithm: str | None = None
	) -> dict[str, list]:
		if sortAlgorithm and sortAlgorithm != "algorithm1":
			raise ValueError(f"Invalid sort algorithm {sortAlgorithm!r}")

		products_by_id_and_version: dict[tuple[str, str, str], LocalbootProduct] = {}
		for product in self.product_getObjects(type="LocalbootProduct"):
			products_by_id_and_version[(product.id, product.productVersion, product.packageVersion)] = product

		product_ids = []
		product_on_clients = []
		for product_on_depot in self.productOnDepot_getObjects(depotId=depotId, productType="LocalbootProduct"):
			product = products_by_id_and_version.get(
				(product_on_depot.productId, product_on_depot.productVersion, product_on_depot.packageVersion)
			)
			if not product:
				continue

			product_ids.append(product.id)
			if not product.setupScript:
				continue

			product_on_clients.append(
				ProductOnClient(
					productId=product_on_depot.productId,
					productType=product_on_depot.productType,
					clientId=depotId,
					installationStatus="not_installed",
					actionRequest="setup",
				)
			)

		product_ids.sort()
		sorted_ids = [
			poc.productId
			for actions in self.get_product_action_groups(product_on_clients).values()
			for a in actions
			for poc in a.product_on_clients
		]
		return {"not_sorted": product_ids, "sorted": sorted_ids}
