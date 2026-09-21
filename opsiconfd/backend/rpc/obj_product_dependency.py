# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.product_dependency
"""

from __future__ import annotations

import os
import re
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from heapq import heappop, heappush
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

import msgspec
from opsi.exception import OpsiError
from opsi.logging import TRACE
from opsi.opsi.service.model.object import LocalbootProduct, Product, ProductDependency, ProductOnClient, ProductOnDepot, serialize
from opsi.opsi.service.model.type import to_list, to_object_class
from opsi.time import unix_timestamp

from opsiconfd.config import PROD_DEP_DEBUG_DIR
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType

ACTION_REQUEST_PRIO = {
	"setup": 1,
	"update": 2,
	"always": 3,
	"once": 4,
	"custom": 5,
	"uninstall": 6,
	"none": 7,
}


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
	sort_log: list[str] = field(default_factory=list)

	def log(self, level: int = TRACE) -> None:
		if not logger.isEnabledFor(level):
			return
		logger.log(level, "=> Product action group (prio %r)", self.priority)
		for product_on_client in self.product_on_clients:
			logger.log(
				level,
				"   -> %s (%d): %s",
				product_on_client.productId,
				self.priorities[product_on_client.productId],
				product_on_client.actionRequest,
			)

	def serialize(self) -> dict[str, Any]:
		ser = asdict(self)
		ser["product_on_clients"] = serialize(ser["product_on_clients"])
		ser["dependencies"] = serialize(ser["dependencies"], deep=True)
		return ser


@dataclass
class ActionGroup:
	priority: int = 0
	actions: list[Action] = field(default_factory=list)
	dependencies: dict[str, list[ProductDependency]] = field(default_factory=dict)
	sort_log: list[str] = field(default_factory=list)

	def sort(self) -> None:
		"""Sort actions topologically, using product priority as a stable tie-breaker."""

		def action_key(action: Action) -> tuple[int, str, int]:
			return (-action.priority, action.product_id, ACTION_REQUEST_PRIO[action.action])

		actions_by_key = {(action.product_id, action.action): action for action in self.actions}
		successors: dict[tuple[str, str], set[tuple[str, str]]] = {key: set() for key in actions_by_key}
		indegree = {key: 0 for key in actions_by_key}
		for action in self.actions:
			action_id = (action.product_id, action.action)
			for requirement_type in ("before", "after"):
				for dependent_action in action.dependent_actions[requirement_type]:
					dependent_id = (dependent_action.product_id, dependent_action.action)
					if not dependent_action.required or dependent_id not in actions_by_key:
						continue
					source, target = (dependent_id, action_id) if requirement_type == "before" else (action_id, dependent_id)
					if target in successors[source]:
						continue
					successors[source].add(target)
					indegree[target] += 1

		available: list[tuple[tuple[int, str, int], tuple[str, str]]] = []
		for key, degree in indegree.items():
			if degree == 0:
				heappush(available, (action_key(actions_by_key[key]), key))

		sorted_actions: list[Action] = []
		while available:
			_sort_key, key = heappop(available)
			sorted_actions.append(actions_by_key[key])
			for successor in sorted(successors[key]):
				indegree[successor] -= 1
				if indegree[successor] == 0:
					heappush(available, (action_key(actions_by_key[successor]), successor))

		if len(sorted_actions) != len(self.actions):
			cyclic_actions = sorted(
				(actions_by_key[key] for key, degree in indegree.items() if degree),
				key=action_key,
			)
			cycle = ", ".join(f"{action.product_id}:{action.action}" for action in cyclic_actions)
			logger.warning("Circular product action dependencies detected: %s", cycle)
			self.sort_log.append(f"Circular dependencies: {cycle}")
			sorted_actions.extend(cyclic_actions)

		self.actions = sorted_actions
		products = ", ".join(f"{action.product_id}:{action.action}({action.priority})" for action in self.actions)
		log = f"Topologically sorted by dependencies, priority, productId and actionRequest: {products}"
		logger.debug(log)
		self.sort_log.append(log)

	def add_action(self, action: Action) -> None:
		self.actions.append(action)
		if not action.required:  # or action.action in ("none", None):
			return
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
	required: bool = True
	# Dependent actions by requirement_type
	dependent_actions: dict[str, list[Action]] = field(default_factory=lambda: defaultdict(list))
	product_on_client: ProductOnClient | None = None
	from_actions: dict[str, list[Action]] = field(default_factory=lambda: defaultdict(list))

	def get_product_on_client(self, client_id: str) -> ProductOnClient:
		product_on_client = (
			self.product_on_client.clone()
			if self.product_on_client
			else ProductOnClient(productId=self.product_id, productType=self.product_type, clientId=client_id)
		)
		product_on_client.actionRequest = self.action if self.required else "none"
		return product_on_client

	def __repr__(self) -> str:
		from_actions = {k: [f"{a.product_id}:{a.action}" for a in v] for k, v in self.from_actions.items()}
		dependent_actions = {k: [f"{a.product_id}:{a.action}" for a in v] for k, v in self.dependent_actions.items()}
		return f"<Action {self.product_id}:{self.action} (priority: {self.priority}, required: {self.required}, from_actions: {from_actions}, dependent_actions: {dependent_actions})>"


class RPCProductDependencyMixin(Protocol):
	def get_product_action_groups(
		self: BackendProtocol,
		product_on_clients: list[ProductOnClient],
		*,
		ignore_unavailable_products: bool = True,
		debug_log: str | None = None,
	) -> dict[str, list[ProductActionGroup]]:
		product_cache: dict[tuple[str, str, str], Product | None] = {}
		product_on_depot_cache: dict[tuple[str, str], ProductOnDepot | None] = {}
		product_on_client_cache: dict[tuple[str, str], ProductOnClient] = {}
		product_dependency_cache: dict[tuple[str, str, str], list[ProductDependency]] = {}
		product_on_clients_by_client_id: dict[str, list[ProductOnClient]] = defaultdict(list)
		rfc_products_by_client_id: dict[str, dict[str, str]] = defaultdict(dict)
		rfc_candidates_by_client_id: dict[str, dict[str, list[ProductOnClient]]] = defaultdict(lambda: defaultdict(list))
		product_ids = set()
		for poc in sorted(product_on_clients, key=lambda product_on_client: (product_on_client.clientId, product_on_client.productId)):
			product_on_clients_by_client_id[poc.clientId].append(poc)
			product_ids.add(poc.productId)
			if "--" in poc.productId:
				base_product_id, _ = poc.productId.split("--", 1)
				rfc_candidates_by_client_id[poc.clientId][base_product_id].append(poc)
		for client_id, candidates_by_product_id in rfc_candidates_by_client_id.items():
			for base_product_id, candidates in candidates_by_product_id.items():
				candidates.sort(key=lambda poc: (poc.actionRequest in (None, "", "none"), poc.productId))
				rfc_products_by_client_id[client_id][base_product_id] = candidates[0].productId
				if len(candidates) > 1:
					logger.warning(
						"Multiple product variants found for %s on client %s, using %s",
						base_product_id,
						client_id,
						candidates[0].productId,
					)
		client_ids = list(product_on_clients_by_client_id)
		client_to_depot = {c2d["clientId"]: c2d["depotId"] for c2d in self.configState_getClientToDepotserver(clientIds=client_ids)}
		depot_ids = list(set(client_to_depot.values()))
		product_action_groups: dict[str, list[ProductActionGroup]] = {c: [] for c in client_ids}
		for product_on_client in self.productOnClient_getObjects(clientId=client_ids):
			product_on_client_cache[(product_on_client.clientId, product_on_client.productId)] = product_on_client
		for product_on_client in product_on_clients:
			product_on_client_cache[(product_on_client.clientId, product_on_client.productId)] = product_on_client

		if product_ids:
			# Prefill caches
			for dependency in self.productDependency_getObjects(productId=list(product_ids)):
				pdkey = (
					dependency.productId,
					dependency.productVersion,
					dependency.packageVersion,
				)
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
				product_cache[pkey] = cast(Product, objs[0]) if objs else None

			product = product_cache[pkey]
			if not product:
				raise OpsiProductNotAvailableError(f"Product {product_id!r} (version: {product_version}-{package_version}) not found")

			return product

		def get_product_on_depot(
			depot_id: str,
			product_id: str,
			product_version: str | None = None,
			package_version: str | None = None,
		) -> ProductOnDepot:
			pkey = (depot_id, product_id)
			if pkey not in product_on_depot_cache:
				objs = self.productOnDepot_getObjects(productId=product_id, depotId=depot_id)
				product_on_depot_cache[pkey] = cast(ProductOnDepot, objs[0]) if objs else None

			product_on_depot = product_on_depot_cache[pkey]
			if (
				not product_on_depot
				or (product_version and product_on_depot.productVersion != product_version)
				or (package_version and product_on_depot.packageVersion != package_version)
			):
				raise OpsiProductNotAvailableOnDepotError(
					f"Product {product_id!r} (version: {product_version}-{package_version}) not found on depot {depot_id}"
				)

			return product_on_depot

		def get_product_dependencies(product_id: str, product_version: str, package_version: str) -> list[ProductDependency]:
			pkey = (product_id, product_version, package_version)
			if pkey not in product_dependency_cache:
				objs = self.productDependency_getObjects(
					productId=product_id,
					productVersion=product_version,
					packageVersion=package_version,
				)
				product_dependency_cache[pkey] = objs
			return product_dependency_cache[pkey]

		def get_product_on_client(product_id: str, product_type: str, client_id: str) -> ProductOnClient:
			pkey = (client_id, product_id)
			if pkey not in product_on_client_cache:
				product_on_client = ProductOnClient(
					productId=product_id,
					productType=product_type,
					clientId=client_id,
				)
				product_on_client.setDefaults()
				product_on_client_cache[pkey] = product_on_client
			return product_on_client_cache[pkey]

		@dataclass
		class ActionSorter:
			client_id: str
			depot_id: str
			groups: list[ActionGroup] = field(default_factory=list)
			unsorted_actions: dict[str, dict[str, Action]] = field(default_factory=lambda: defaultdict(dict))
			dependencies: dict[str, list[ProductDependency]] = field(default_factory=lambda: defaultdict(list))
			pending_actions: list[Action] = field(default_factory=list)
			processed_action_ids: set[tuple[str, str]] = field(default_factory=set)

			def process_dependencies(self, action: Action) -> None:
				"""Expand the direct dependencies of one product action."""
				action_id = (action.product_id, action.action)
				if action_id in self.processed_action_ids:
					return
				self.processed_action_ids.add(action_id)
				try:
					product_on_depot = get_product_on_depot(depot_id=self.depot_id, product_id=action.product_id)
					product = get_product(
						product_id=action.product_id,
						product_version=product_on_depot.productVersion,
						package_version=product_on_depot.packageVersion,
					)
				except (
					OpsiProductNotAvailableError,
					OpsiProductNotAvailableOnDepotError,
				) as err:
					if not ignore_unavailable_products:
						raise
					logger.info(err)
					return

				for dependency in get_product_dependencies(
					product_id=product.id,
					product_version=product.productVersion,
					package_version=product.packageVersion,
				):
					if dependency.productAction != action.action:
						continue

					if dependency not in self.dependencies[product.id]:
						logger.debug("New dependency found: %r", dependency)
						self.dependencies[product.id].append(dependency)

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
					except (
						OpsiProductNotAvailableError,
						OpsiProductNotAvailableOnDepotError,
					) as err:
						if not ignore_unavailable_products:
							raise
						logger.info(err)
						continue

					dep_poc = get_product_on_client(
						product_id=dep_product.id,
						product_type=dep_product.getType(),
						client_id=client_id,
					)
					if dep_poc.actionRequest in (None, "none") and rfc_products_by_client_id:
						rfc_product_id = rfc_products_by_client_id.get(client_id, {}).get(dep_product.id)
						if rfc_product_id:
							# There is an action request set for a RFC product and not for the base product
							# Use the RFC product for the dependency
							try:
								dep_product_on_depot = get_product_on_depot(
									depot_id=self.depot_id,
									product_id=rfc_product_id,
									product_version=dependency.requiredProductVersion,
									package_version=dependency.requiredPackageVersion,
								)
								dep_product = get_product(
									product_id=rfc_product_id,
									product_version=dep_product_on_depot.productVersion,
									package_version=dep_product_on_depot.packageVersion,
								)
								dep_poc_rfc = get_product_on_client(
									product_id=dep_product.id,
									product_type=dep_product.getType(),
									client_id=client_id,
								).clone()
								if dep_poc.installationStatus == "installed":
									dep_poc_rfc.installationStatus = "installed"
								dep_poc = dep_poc_rfc
								logger.info("Using rfc product: %s", dep_poc_rfc)
							except (
								OpsiProductNotAvailableError,
								OpsiProductNotAvailableOnDepotError,
							) as err:
								logger.debug("RFC product not available: %s", err)

					required_action = dependency.requiredAction
					required = True
					if not required_action:
						if dependency.requiredInstallationStatus == "installed":
							required_action = "setup"
						elif dependency.requiredInstallationStatus == "not_installed":
							required_action = "uninstall"
						else:
							raise ValueError(f"Invalid requiredInstallationStatus: '{dependency.requiredInstallationStatus}'")

						required = not (
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
						)

					assert required_action

					if required and not getattr(dep_product, f"{required_action}Script"):
						logger.warning(
							"%r cannot be fulfilled because product %r is missing a %sScript",
							dependency,
							dep_product,
							required_action,
						)
						continue

					req_type = dependency.requirementType or ""
					dep_action = self.unsorted_actions[dep_product.id].get(required_action)
					if dep_action:
						if not dep_action.required:
							dep_action.required = required
						if not any(
							a.product_id == action.product_id and a.action == action.action for a in dep_action.from_actions[req_type]
						):
							dep_action.from_actions[req_type].append(action)
					else:
						dep_action = Action(
							product_id=dep_product.id,
							product_type=dep_product.getType(),
							action=required_action,
							priority=(dep_product.priority or 0) * (-1 if required_action == "uninstall" else 1),
							required=required,
						)
						dep_action.from_actions[req_type].append(action)
						logger.debug("Adding dependent action: %r", dep_action)
						self.unsorted_actions[dep_product.id][required_action] = dep_action

					if not any(
						dep_action.product_id == cur_act.product_id and dep_action.action == cur_act.action
						for cur_act in action.dependent_actions[req_type]
					):
						logger.trace(
							"Adding dependent action: %s:%s => %s:%s:%s",
							action.product_id,
							action.action,
							dep_action.product_id,
							dep_action.action,
							req_type,
						)
						action.dependent_actions[req_type].append(dep_action)

					self.pending_actions.append(dep_action)

			def process_product_on_clients(self, product_on_clients: list[ProductOnClient]) -> None:
				logger.debug("Add ProductOnClients to unsorted actions")
				for poc in product_on_clients:
					self.add_product_on_client(poc)

				logger.debug("Add dependent actions to unsorted actions")
				for act_actions in list(self.unsorted_actions.values()):
					for act_action in act_actions.values():
						self.pending_actions.append(act_action)
				while self.pending_actions:
					self.process_dependencies(self.pending_actions.pop())

				logger.trace("Dependencies: %r", self.dependencies)

				logger.debug("Select the appropriate product actions")
				for product_id, ar_actions in self.unsorted_actions.items():
					if len(ar_actions) <= 1:
						continue
					logger.trace("Actions %r: %s", product_id, ar_actions)
					product_on_client = next(
						(a.product_on_client for a in ar_actions.values() if a.product_on_client),
						None,
					)

					actions = sorted(
						ar_actions.values(),
						key=lambda a: (
							not a.required,
							ACTION_REQUEST_PRIO[a.action],
							-sum(len(actions) for actions in a.from_actions.values()),
							a.product_id,
							a.action,
						),
					)

					actions[0].product_on_client = product_on_client
					# Set all other actions to not required
					for action in actions[1:]:
						action.required = False
						action.product_on_client = None

					if (
						len(actions) == 2
						and actions[0].action == "uninstall"
						and actions[0].required
						and actions[1].action == "setup"
						and not actions[1].required
						and actions[1].from_actions["before"]
					):
						# Handle the scenario where a product requires another product to be installed
						# for its own uninstallation and the required product is already installed and
						# also scheduled for uninstallation. In this case, ensure the required product
						# is only uninstalled after the product which depends on it.
						for action in actions[1].from_actions["before"]:
							for dep_action in action.dependent_actions["before"]:
								if dep_action == actions[1]:
									logger.debug("Adding action %s to from_actions['after']", action)
									actions[0].from_actions["after"].append(action)
									action.dependent_actions["after"].append(actions[0])

					logger.trace("Actions %r: %s", product_id, ar_actions)

				logger.debug("Build and sort action groups")
				connected_products: dict[str, set[str]] = {product_id: set() for product_id in self.unsorted_actions}
				for product_id, ar_actions in self.unsorted_actions.items():
					for action in ar_actions.values():
						if not action.required:
							continue
						for requirement_type in ("before", "after"):
							for dependent_action in action.dependent_actions[requirement_type]:
								if dependent_action.product_id not in connected_products:
									continue
								connected_products[product_id].add(dependent_action.product_id)
								connected_products[dependent_action.product_id].add(product_id)

				product_groups: list[set[str]] = []
				unvisited_product_ids = set(connected_products)
				while unvisited_product_ids:
					start_product_id = min(unvisited_product_ids)
					product_ids: set[str] = set()
					pending_product_ids = [start_product_id]
					while pending_product_ids:
						current_product_id = pending_product_ids.pop()
						if current_product_id not in unvisited_product_ids:
							continue
						unvisited_product_ids.remove(current_product_id)
						product_ids.add(current_product_id)
						pending_product_ids.extend(sorted(connected_products[current_product_id], reverse=True))
					product_groups.append(product_ids)

				for product_ids in product_groups:
					group = ActionGroup(dependencies={pid: dep for pid, dep in self.dependencies.items() if pid in product_ids})
					for product_id in sorted(product_ids):
						if ar_actions := self.unsorted_actions.pop(product_id, {}):
							added = False
							action_with_poc: Action | None = None
							for action in ar_actions.values():
								if action.required:
									group.add_action(action)
									added = True
								elif action.product_on_client:
									action_with_poc = action
							if not added and action_with_poc:
								group.add_action(action_with_poc)

					if group.actions:
						group.sort()
						self.groups.append(group)

				logger.debug("Sort action groups by priority")
				self.groups.sort(
					key=lambda group: (
						-group.priority,
						tuple((action.product_id, ACTION_REQUEST_PRIO[action.action]) for action in group.actions),
					)
				)

			def add_product_on_client(self, product_on_client: ProductOnClient) -> None:
				try:
					product_on_depot = get_product_on_depot(depot_id=self.depot_id, product_id=product_on_client.productId)
					product = get_product(
						product_id=product_on_client.productId,
						product_version=product_on_depot.productVersion,
						package_version=product_on_depot.packageVersion,
					)
				except (
					OpsiProductNotAvailableError,
					OpsiProductNotAvailableOnDepotError,
				) as err:
					if not ignore_unavailable_products:
						raise
					logger.info(err)
					return

				action = Action(
					product_id=product_on_client.productId,
					product_type=product_on_client.productType,
					action=product_on_client.actionRequest or "none",
					priority=(product.priority or 0) * (-1 if product_on_client.actionRequest == "uninstall" else 1),
					product_on_client=product_on_client,
					required=product_on_client.actionRequest not in (None, "", "none"),
				)
				self.unsorted_actions[action.product_id][action.action] = action

		for client_id, pocs in product_on_clients_by_client_id.items():
			product_action_groups[client_id] = []
			depot_id = client_to_depot.get(client_id, client_id)

			action_sorter = ActionSorter(client_id=client_id, depot_id=depot_id)
			action_sorter.process_product_on_clients(pocs)

			# Build ProductActionGroups and add action_sequence to ProductOnClient objects
			action_sequence = 0
			for a_group in action_sorter.groups:
				group = ProductActionGroup(
					priority=a_group.priority,
					dependencies=a_group.dependencies,
					sort_log=a_group.sort_log,
				)
				for action in a_group.actions:
					if not action.required and not action.product_on_client:
						continue
					group.priorities[action.product_id] = action.priority
					poc = action.get_product_on_client(client_id)
					if action.required and action.action and action.action != "none":
						poc.actionSequence = action_sequence
						action_sequence += 1
					else:
						poc.actionSequence = -1
					group.product_on_clients.append(poc)
				if group.product_on_clients:
					product_action_groups[client_id].append(group)
					group.log()

			if debug_log:
				self._write_debug_log(debug_log, client_id, product_action_groups[client_id])

		return product_action_groups

	def _write_debug_log(
		self,
		prefix: str,
		client_id: str,
		product_action_groups: list[ProductActionGroup],
	) -> None:
		debug_dir = Path(PROD_DEP_DEBUG_DIR)
		debug_dir.mkdir(parents=True, exist_ok=True)
		now = int(unix_timestamp() * 1_000_000)
		prefix = f"{prefix}-" if prefix else ""
		prefix = re.sub(r"[\s\./]", "_", f"{prefix}{client_id}-{now}-")
		with tempfile.NamedTemporaryFile(delete=False, dir=PROD_DEP_DEBUG_DIR, prefix=prefix, suffix=".log") as log_file:
			logger.notice("Writing product action group debug log to: %s", log_file.name)
			log_file.write(msgspec.json.encode([g.serialize() for g in product_action_groups]))
			os.chmod(log_file.name, 0o666)

	def productDependency_bulkInsertObjects(
		self: BackendProtocol,
		productDependencies: list[dict] | list[ProductDependency],
	) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_DEPENDENCY", objs=productDependencies)  # ty: ignore[invalid-argument-type]

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_insertObject(
		self: BackendProtocol,
		productDependency: dict | ProductDependency,
	) -> None:
		ace = self._get_ace("productDependency_insertObject")
		productDependency = to_object_class(productDependency, ProductDependency)
		self._mysql.insert_object(
			table="PRODUCT_DEPENDENCY",
			obj=productDependency,
			ace=ace,
			create=True,
			set_null=True,
		)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_updateObject(
		self: BackendProtocol,
		productDependency: dict | ProductDependency,
	) -> None:
		ace = self._get_ace("productDependency_updateObject")
		productDependency = to_object_class(productDependency, ProductDependency)
		self._mysql.insert_object(
			table="PRODUCT_DEPENDENCY",
			obj=productDependency,
			ace=ace,
			create=False,
			set_null=False,
		)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_createObjects(
		self: BackendProtocol,
		productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency,
	) -> None:
		ace = self._get_ace("productDependency_createObjects")
		with self._mysql.session() as session:
			for productDependency in to_list(productDependencies):
				productDependency = to_object_class(productDependency, ProductDependency)
				self._mysql.insert_object(
					table="PRODUCT_DEPENDENCY",
					obj=productDependency,
					ace=ace,
					create=True,
					set_null=True,
					session=session,
				)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_updateObjects(
		self: BackendProtocol,
		productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency,
	) -> None:
		ace = self._get_ace("productDependency_updateObjects")
		with self._mysql.session() as session:
			for productDependency in to_list(productDependencies):
				productDependency = to_object_class(productDependency, ProductDependency)
				self._mysql.insert_object(
					table="PRODUCT_DEPENDENCY",
					obj=productDependency,
					ace=ace,
					create=True,
					set_null=False,
					session=session,
				)

	@rpc_method(check_acl=False)
	def productDependency_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[ProductDependency]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_DEPENDENCY",
			ace=ace,
			object_type=ProductDependency,
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(
		deprecated=True,
		alternative_method="productDependency_getObjects",
		check_acl=False,
	)
	def productDependency_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_DEPENDENCY",
			object_type=ProductDependency,
			ace=ace,
			return_type="dict",
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def productDependency_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_idents(
			table="PRODUCT_DEPENDENCY",
			object_type=ProductDependency,
			ace=ace,
			ident_type=returnType,
			filter=filter,
		)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_deleteObjects(
		self: BackendProtocol,
		productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency,
	) -> None:
		if not productDependencies:
			return
		ace = self._get_ace("productDependency_deleteObjects")
		self._mysql.delete_objects(
			table="PRODUCT_DEPENDENCY",
			object_type=ProductDependency,
			obj=productDependencies,
			ace=ace,
		)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_create(
		self: BackendProtocol,
		productId: str,
		productVersion: str,
		packageVersion: str,
		productAction: str,
		requiredProductId: str | None = None,
		requiredProductVersion: str | None = None,
		requiredPackageVersion: str | None = None,
		requiredAction: str | None = None,
		requiredInstallationStatus: str | None = None,
		requirementType: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productDependency_createObjects(ProductDependency.fromHash(_hash))

	@rpc_method(check_acl=False)
	def productDependency_delete(
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
	def getProductOrdering(self: BackendProtocol, depotId: str, sortAlgorithm: str | None = None) -> dict[str, list]:
		if sortAlgorithm and sortAlgorithm != "algorithm1":
			raise ValueError(f"Invalid sort algorithm {sortAlgorithm!r}")

		products_by_id_and_version: dict[tuple[str, str, str], LocalbootProduct] = {}
		for product in self.product_getObjects(type="LocalbootProduct"):
			products_by_id_and_version[(product.id, product.productVersion, product.packageVersion)] = product

		product_ids = []
		product_on_clients = []
		for product_on_depot in self.productOnDepot_getObjects(depotId=depotId, productType="LocalbootProduct"):
			product = products_by_id_and_version.get(
				(
					product_on_depot.productId,
					product_on_depot.productVersion,
					product_on_depot.packageVersion,
				)
			)
			if not product:
				continue

			product_ids.append(product.id)

			for action in ("setup", "update", "always", "once", "custom", "uninstall"):
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
