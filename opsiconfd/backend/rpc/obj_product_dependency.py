# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.product_dependency
"""

from __future__ import annotations

import os
import re
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import msgspec
from opsicommon.exceptions import OpsiError
from opsicommon.logging.constants import TRACE
from opsicommon.objects import (
	LocalbootProduct,
	Product,
	ProductDependency,
	ProductOnClient,
	ProductOnDepot,
	serialize,
)
from opsicommon.types import (
	forceList,
	forceObjectClass,
)
from opsicommon.utils import unix_timestamp

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
		logger.debug("Sort actions by priority, productId and actionRequest")
		self.actions.sort(key=lambda a: (a.priority * -1, a.product_id, ACTION_REQUEST_PRIO[a.action]))
		prods = [f"{a.product_id}:{a.action}({a.priority})" for a in self.actions]
		log = f"Ordered by priority, productId and actionRequest: {', '.join(prods)}"
		logger.debug(log)
		self.sort_log.append(log)

		dependent_actions: dict[str, list[Action]] = {
			"before": [],
			"after": [],
		}
		for action in self.actions:
			for requirement_type, dep_actions in action.dependent_actions.items():
				if requirement_type not in ("before", "after"):
					continue
				for dep_action in dep_actions:
					if dep_action.required and dep_action not in dependent_actions[requirement_type]:
						dependent_actions[requirement_type].append(dep_action)

		dependent_actions["before"].sort(key=lambda a: (a.priority * -1, a.product_id, ACTION_REQUEST_PRIO[a.action]))
		dependent_actions["after"].sort(key=lambda a: (a.priority, a.product_id, ACTION_REQUEST_PRIO[a.action]))

		run_number = 0
		while run_number < len(self.actions):
			run_number += 1
			changes = 0
			logger.debug("Dependency sort run #%d", run_number)
			for requirement_type in ("before", "after"):
				for dep_action in dependent_actions[requirement_type]:
					logger.trace(
						"Processing dependent action: %r - %r - %r",
						dep_action.product_id,
						dep_action.action,
						requirement_type,
					)
					for action in dep_action.from_actions:
						logger.trace("Processing action: %r - %r", action.product_id, action.action)

						pos_prd = -1
						pos_dep = -1

						for idx, act in enumerate(self.actions):
							if act.product_id == action.product_id:
								pos_prd = idx
							elif act.product_id == dep_action.product_id:
								pos_dep = idx
							if pos_prd > -1 and pos_dep > -1:
								break

						move_direction = (
							requirement_type
							if (requirement_type == "before" and pos_dep > pos_prd) or (requirement_type == "after" and pos_dep < pos_prd)
							else None
						)
						if not move_direction:
							continue

						log = (
							f"Sort run #{run_number}: Moving {dep_action.product_id}:{dep_action.action} (#{pos_dep}) "
							f"{move_direction} {action.product_id}:{action.action} (#{pos_prd})"
						)
						logger.debug(log)
						self.sort_log.append(log)
						self.actions.insert(pos_prd, self.actions.pop(pos_dep))

			prods = [f"{a.product_id}:{a.action}({a.priority})" for a in self.actions]
			log = f"Order after sort run #{run_number}: {', '.join(prods)}"
			logger.debug(log)
			self.sort_log.append(log)
			if not changes:
				logger.debug("Sort run finished after %d iterations", run_number)
				break

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
	from_actions: list[Action] = field(default_factory=list)

	def get_product_on_client(self, client_id: str) -> ProductOnClient:
		product_on_client = (
			self.product_on_client.clone()
			if self.product_on_client
			else ProductOnClient(productId=self.product_id, productType=self.product_type, clientId=client_id)
		)
		product_on_client.actionRequest = self.action if self.required else "none"
		return product_on_client

	def __repr__(self) -> str:
		from_actions = [f"{a.product_id}:{a.action}" for a in self.from_actions]
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
				product_cache[pkey] = objs[0] if objs else None
			if not product_cache[pkey]:
				raise OpsiProductNotAvailableError(f"Product {product_id!r} (version: {product_version}-{package_version}) not found")

			return product_cache[pkey]

		def get_product_on_depot(
			depot_id: str,
			product_id: str,
			product_version: str | None = None,
			package_version: str | None = None,
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
					productId=product_id,
					productVersion=product_version,
					packageVersion=package_version,
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
					poc = ProductOnClient(
						productId=product_id,
						productType=product_type,
						clientId=client_id,
					)
					poc.setDefaults()
					objs = [poc]
				product_on_client_cache[pkey] = objs[0]
			return product_on_client_cache[pkey]

		@dataclass
		class ActionSorter:
			client_id: str
			depot_id: str
			groups: list[ActionGroup] = field(default_factory=list)
			unsorted_actions: dict[str, dict[str, Action]] = field(default_factory=lambda: defaultdict(dict))
			dependencies: dict[str, list[ProductDependency]] = field(default_factory=lambda: defaultdict(list))

			def process_dependencies(
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
					if dependency.productAction != action.action or dependency.requiredProductId in dependency_path:
						continue

					logger.debug("Dependency found: %r", dependency)
					if dependency not in self.dependencies[product.id]:
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

					dep_action = self.unsorted_actions[dep_product.id].get(required_action)
					if dep_action:
						if not dep_action.required:
							dep_action.required = required
						if not any(a.product_id == action.product_id and a.action == action.action for a in dep_action.from_actions):
							dep_action.from_actions.append(action)
					else:
						dep_action = Action(
							product_id=dep_product.id,
							product_type=dep_product.getType(),
							action=required_action,
							priority=(dep_product.priority or 0) * (-1 if required_action == "uninstall" else 1),
							required=required,
							from_actions=[action],
						)
						logger.debug("Adding dependent action: %r", dep_action)
						self.unsorted_actions[dep_product.id][required_action] = dep_action

					req_type = dependency.requirementType or ""
					if not any(
						dep_action.product_id == cur_act.product_id and dep_action.action == cur_act.action
						for cur_act in action.dependent_actions[req_type]
					):
						action.dependent_actions[req_type].append(dep_action)

					self.process_dependencies(
						action=dep_action,
						dependency_path=dependency_path,
					)

			def process_product_on_clients(self, product_on_clients: list[ProductOnClient]) -> None:
				logger.debug("Add ProductOnClients to unsorted actions")
				for poc in product_on_clients:
					self.add_product_on_client(poc)

				logger.debug("Add dependent actions to unsorted actions")
				for act_actions in list(self.unsorted_actions.values()):
					for act_action in act_actions.values():
						self.process_dependencies(act_action)

				logger.trace("Dependencies: %r", self.dependencies)

				logger.debug("Select the appropriate product actions")
				for product_id, ar_actions in self.unsorted_actions.items():
					if len(ar_actions) <= 1:
						continue
					logger.trace("Actions: %s", ar_actions)
					product_on_client = next(
						(a.product_on_client for a in ar_actions.values() if a.product_on_client),
						None,
					)
					actions = sorted(
						list(ar_actions.values()),
						key=lambda a: (ACTION_REQUEST_PRIO[a.action], len(a.from_actions)),
					)

					actions[0].product_on_client = product_on_client
					# Set all other actions to not required
					for action in actions[1:]:
						action.required = False
						action.product_on_client = None

					logger.trace("Actions: %s", ar_actions)

				logger.debug("Build and sort action groups")
				p_groups: list[set[str]] = []
				for product_id, ar_actions in self.unsorted_actions.items():
					product_ids = {product_id}
					for action in ar_actions.values():
						if not action.required:
							continue
						for (
							requirement_type,
							dep_actions,
						) in action.dependent_actions.items():
							if requirement_type:
								for dep_action in dep_actions:
									product_ids.add(dep_action.product_id)

					group_idx: set[int] = set()
					for pid in list(product_ids):
						for idx, pids in enumerate(p_groups):
							if pid in pids:
								product_ids.update(pids)
								group_idx.add(idx)

					p_groups = [pids for idx, pids in enumerate(p_groups) if idx not in group_idx]
					p_groups.append(product_ids)

				for product_ids in p_groups:
					group = ActionGroup()
					for product_id in product_ids:
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
				self.groups.sort(key=lambda g: g.priority, reverse=True)

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
		self._mysql.bulk_insert_objects(table="PRODUCT_DEPENDENCY", objs=productDependencies)  # type: ignore[arg-type]

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_insertObject(
		self: BackendProtocol,
		productDependency: dict | ProductDependency,
	) -> None:
		ace = self._get_ace("productDependency_insertObject")
		productDependency = forceObjectClass(productDependency, ProductDependency)
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
		productDependency = forceObjectClass(productDependency, ProductDependency)
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
			for productDependency in forceList(productDependencies):
				productDependency = forceObjectClass(productDependency, ProductDependency)
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
			for productDependency in forceList(productDependencies):
				productDependency = forceObjectClass(productDependency, ProductDependency)
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
