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
	priorities: dict[str, int] = field(default_factory=dict)
	dependencies: dict[str, list[ProductDependency]] = field(default_factory=lambda: defaultdict(list))

	def log(self, level: int = TRACE) -> None:
		if not logger.isEnabledFor(level):
			return
		logger.log(level, "=> Product action group (prio %r)", self.priority)
		for product_on_clients in self.product_on_clients:
			logger.log(level, "   -> %s: %s", product_on_clients.productId, product_on_clients.actionRequest)


@dataclass
class ActionGroup:
	priority: int = 0
	actions: list[Action] = field(default_factory=list)
	dependencies: dict[str, list[ProductDependency]] = field(default_factory=dict)

	def sort(self) -> None:
		logger.debug("Sort actions by priority")
		self.actions.sort(key=lambda a: a.priority, reverse=True)

		run_number = 0
		while run_number < len(self.actions):
			logger.debug("Dependency sort run #%d", run_number)
			run_number += 1
			actions = self.actions.copy()
			for action in actions:
				for dependency in self.dependencies.get(action.product_id, []):
					pos_prd = -1
					pos_req = -1
					for idx, act in enumerate(self.actions):
						if act.product_id == action.product_id:
							pos_prd = idx
						elif act.product_id == dependency.requiredProductId:
							pos_req = idx
						if pos_prd > -1 and pos_req > -1:
							break

					if dependency.requirementType == "before":
						if pos_req > pos_prd:
							self.actions.insert(pos_prd, self.actions.pop(pos_req))
					elif dependency.requirementType == "after":
						if pos_req < pos_prd:
							self.actions.insert(pos_prd + 1, self.actions.pop(pos_req))
			if actions == self.actions:
				logger.debug("Sort run finished after %d iterations", run_number)
				break

	def add_action(self, action: Action) -> None:
		self.actions.append(action)
		max_priority = max(self.priority, action.priority)
		min_priority = min(self.priority, action.priority)
		if max_priority > 0:
			# Prefer highest priority > 0
			self.priority = max_priority
		elif min_priority < 0:
			# After that prefer lowest priority < 0
			self.priority = min_priority


@dataclass
class Action:
	product_id: str
	product_type: str
	action: str
	priority: int = 0
	product_on_client: ProductOnClient | None = None

	def get_product_on_client(self, client_id: str) -> ProductOnClient:
		product_on_client = (
			self.product_on_client.clone()
			if self.product_on_client
			else ProductOnClient(productId=self.product_id, productType=self.product_type, clientId=client_id)
		)
		product_on_client.actionRequest = self.action
		return product_on_client


class RPCProductDependencyMixin(Protocol):
	def get_product_action_groups(  # pylint: disable=too-many-locals,too-many-statements,too-many-branches
		self: BackendProtocol, product_on_clients: list[ProductOnClient], *, ignore_unavailable_products: bool = True
	) -> dict[str, list[ProductActionGroup]]:
		product_cache: dict[tuple[str, str, str], Product] = {}
		product_on_depot_cache: dict[tuple[str, str], ProductOnDepot] = {}
		product_on_client_cache: dict[tuple[str, str], ProductOnClient] = {}
		product_dependency_cache: dict[tuple[str, str, str], list[ProductDependency]] = {}
		product_on_clients_by_client_id: dict[str, list[ProductOnClient]] = defaultdict(list)
		product_ids = set()
		for poc in product_on_clients:
			product_on_clients_by_client_id[poc.clientId].append(poc)
			product_ids.add(poc.productId)
		client_ids = list(product_on_clients_by_client_id)
		client_to_depot = {c2d["clientId"]: c2d["depotId"] for c2d in self.configState_getClientToDepotserver(clientIds=client_ids)}
		depot_ids = list(set(client_to_depot.values()))
		product_action_groups: dict[str, list[ProductActionGroup]] = {c: [] for c in client_ids}

		if product_ids:
			# Prefill caches
			for dependency in self.productDependency_getObjects(productId=list(product_ids)):
				pdkey = (dependency.productId, dependency.productVersion, dependency.packageVersion)
				if pdkey not in product_dependency_cache:
					product_dependency_cache[pdkey] = []
				product_dependency_cache[pdkey].append(dependency)
				product_ids.add(dependency.requiredProductId)

			for product in self.product_getObjects(id=list(product_ids)):
				pkey = (product.id, product.productVersion, product.packageVersion)
				product_cache[pkey] = product

			if depot_ids:
				for product_on_depot in self.productOnDepot_getObjects(productId=list(product_ids), depotId=depot_ids):
					podkey = (product_on_depot.depotId, product_on_depot.productId)
					product_on_depot_cache[podkey] = product_on_depot

		def get_product(product_id: str, product_version: str, package_version: str) -> Product:
			pkey = (product_id, product_version, package_version)
			if pkey not in product_cache:
				objs = self.product_getObjects(
					id=product_id,
					productVersion=product_version,
					packageVersion=package_version,
				)
				product_cache[pkey] = objs[0] if objs else None
			if not product_cache[pkey]:
				raise OpsiProductNotAvailableError(f"Product {product_id!r} (version: {product_version}-{package_version}) not found")

			return product_cache[pkey]

		def get_product_on_depot(
			depot_id: str, product_id: str, product_version: str | None = None, package_version: str | None = None
		) -> ProductOnDepot:
			pkey = (depot_id, product_id)
			if pkey not in product_on_depot_cache:
				objs = self.productOnDepot_getObjects(productId=product_id, depotId=depot_id)
				product_on_depot_cache[pkey] = objs[0] if objs else None

			if (
				not product_on_depot_cache[pkey]
				or (product_version and product_on_depot_cache[pkey].productVersion != product_version)
				or (package_version and product_on_depot_cache[pkey].packageVersion != package_version)
			):
				raise OpsiProductNotAvailableOnDepotError(
					f"Product {product_id!r} (version: {product_version}-{package_version}) not found on depot {depot_id}"
				)

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
			groups: list[ActionGroup] = field(default_factory=list)
			unsorted_actions: dict[str, list[Action]] = field(default_factory=lambda: defaultdict(list))
			product_id_groups: list[set[str]] = field(default_factory=list)
			dependencies: dict[str, list[ProductDependency]] = field(default_factory=lambda: defaultdict(list))

			def process_dependencies(  # pylint: disable=too-many-arguments,too-many-branches
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

					logger.debug("Dependency found: %r", dependency)
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

					if dependency.requirementType:
						# Only "hard" requirements should affect action order
						if dependency not in self.dependencies[product.id]:
							self.dependencies[product.id].append(dependency)
							group_idx = -1
							for product_id in action.product_id, dep_product.id:
								for idx, product_group in enumerate(self.product_id_groups):
									if product_id in product_group:
										group_idx = idx
										break
							if group_idx == -1:
								self.product_id_groups.append({action.product_id, dep_product.id})
							else:
								self.product_id_groups[group_idx].add(action.product_id)
								self.product_id_groups[group_idx].add(dep_product.id)

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

					if not getattr(dep_product, f"{required_action}Script"):
						logger.warning(
							"%r cannot be fulfilled because product %r is missing a %sScript", dependency, dep_product, required_action
						)
						continue

					dep_action = Action(
						product_id=dep_product.id,
						product_type=dep_product.getType(),
						action=required_action,
						priority=dep_product.priority or 0,
					)
					self.unsorted_actions[dep_action.product_id].append(dep_action)

					self.process_dependencies(
						action=dep_action,
						dependency_path=dependency_path,
					)

			def process_product_on_clients(self, product_on_clients: list[ProductOnClient]) -> None:
				logger.debug("Add ProductOnClients to unsorted actions")
				for poc in product_on_clients:
					self.add_product_on_client(poc)

				logger.debug("Add dependent actions to unsorted actions")
				for actions in list(self.unsorted_actions.values()):
					for action in actions:
						self.process_dependencies(action)

				logger.debug("Merge duplicate actions")
				for product_id, actions in self.unsorted_actions.items():
					if len(actions) <= 1:
						continue
					action = actions[0]
					product_on_client = None
					for act in actions:
						if not product_on_client and act.product_on_client:
							product_on_client = act.product_on_client
						if not act.action or act.action == "none":
							continue
						action = act
					action.product_on_client = product_on_client
					self.unsorted_actions[product_id] = [action]

				logger.debug("Build and sort action groups")
				for product_id_group in self.product_id_groups:
					group = ActionGroup()
					for product_id in product_id_group:
						actions = self.unsorted_actions.pop(product_id, [])
						if actions:
							group.add_action(actions[0])
							dependencies = self.dependencies.get(actions[0].product_id)
							if dependencies:
								group.dependencies[actions[0].product_id] = dependencies
					group.sort()
					self.groups.append(group)

				logger.debug("Add remaining independent actions")
				for product_id, actions in self.unsorted_actions.items():
					group = ActionGroup()
					group.add_action(actions[0])
					self.groups.append(group)

				logger.debug("Sort action groups by priority")
				self.groups.sort(key=lambda g: g.priority, reverse=True)

			def add_product_on_client(self, product_on_client: ProductOnClient) -> None:
				try:
					product_on_depot = get_product_on_depot(depot_id=self.depot_id, product_id=product_on_client.productId)
					product = get_product(
						product_id=product_on_client.productId,
						product_version=product_on_depot.productVersion,
						package_version=product_on_depot.packageVersion,
					)
				except (OpsiProductNotAvailableError, OpsiProductNotAvailableOnDepotError) as err:
					if not ignore_unavailable_products:
						raise
					logger.info(err)
					return

				action = Action(
					product_id=product_on_client.productId,
					product_type=product_on_client.productType,
					action=product_on_client.actionRequest or "none",
					priority=product.priority or 0,
					product_on_client=product_on_client,
				)
				self.unsorted_actions[action.product_id].append(action)

		for client_id, pocs in product_on_clients_by_client_id.items():
			product_action_groups[client_id] = []
			depot_id = client_to_depot.get(client_id, client_id)

			action_sorter = ActionSorter(client_id=client_id, depot_id=depot_id)
			action_sorter.process_product_on_clients(pocs)

			# Build ProductActionGroups and add action_sequence to ProductOnClient objects
			action_sequence = 0
			for a_group in action_sorter.groups:
				group = ProductActionGroup(priority=a_group.priority, dependencies=a_group.dependencies)
				for action in a_group.actions:
					group.priorities[action.product_id] = action.priority
					poc = action.get_product_on_client(client_id)
					if action.action and action.action != "none":
						poc.actionSequence = action_sequence
						action_sequence += 1
					else:
						poc.actionSequence = -1
					group.product_on_clients.append(poc)
				product_action_groups[client_id].append(group)
				group.log()

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

			for action in ("setup", "always", "once", "custom", "uninstall"):
				if getattr(product, f"{action}Script"):
					product_on_clients.append(
						ProductOnClient(
							productId=product_on_depot.productId,
							productType=product_on_depot.productType,
							clientId=depotId,
							installationStatus="not_installed",
							actionRequest=action,
						)
					)
					break

		product_ids.sort()
		sorted_ids = [
			poc.productId
			for actions in self.get_product_action_groups(product_on_clients).values()
			for a in actions
			for poc in a.product_on_clients
		]
		return {"not_sorted": product_ids, "sorted": sorted_ids}
