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


class RPCProductDependencyMixin(Protocol):
	def get_product_action_groups(  # pylint: disable=too-many-locals,too-many-statements
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

		def add_product_on_client(  # pylint: disable=too-many-locals,too-many-branches
			product_action_groups: list[ProductActionGroup],
			product_on_client: ProductOnClient,
			group: ProductActionGroup | None = None,
			group_idx: int = 0,
			dependencies_processed: list[str] | None = None,
		) -> None:
			logger.debug("add_product_on_client: %s", product_on_client)
			dependencies_processed = dependencies_processed or []
			for product_action_group in product_action_groups:
				for poc in product_action_group.product_on_clients:
					if poc.productId == product_on_client.productId:
						if poc.actionRequest != product_on_client.actionRequest:
							logger.warning(
								"Product %r was already requested with action %r, now requested with action %r",
								poc.productId,
								poc.actionRequest,
								product_on_client.actionRequest,
							)
						if not group:
							# Not as dependency, keep
							return
						# Add as dependency, replace
						idx = product_action_group.product_on_clients.index(poc)
						product_action_group.product_on_clients.pop(idx)
						if group and group == product_action_group and idx < group_idx:
							group_idx -= 1
						break

			depot_id = client_to_depot.get(product_on_client.clientId, product_on_client.clientId)
			try:
				product_on_depot = get_product_on_depot(depot_id=depot_id, product_id=product_on_client.productId)
				product_on_client.productVersion = product_on_depot.productVersion
				product_on_client.packageVersion = product_on_depot.packageVersion
				product = get_product(
					product_id=product_on_client.productId,
					product_version=product_on_client.productVersion,
					package_version=product_on_client.packageVersion,
				)
			except (OpsiProductNotAvailableError, OpsiProductNotAvailableOnDepotError) as err:
				if not ignore_unavailable_products:
					raise
				logger.info(err)
				return

			dependencies = [
				d
				for d in get_product_dependencies(
					product_id=product_on_client.productId,
					product_version=product_on_client.productVersion,
					package_version=product_on_client.packageVersion,
				)
				if d.productAction == product_on_client.actionRequest
			]
			if not group:
				group = ProductActionGroup()
				product_action_groups.append(group)

			group.product_on_clients.insert(group_idx, product_on_client)
			product_priority = product.priority or 0
			if product_priority > 0 and product_priority > group.priority:
				# Prefer highest priority > 0
				group.priority = product_priority
			elif product_priority < 0 and group.priority <= 0 and product_priority < group.priority:
				# After that prefer lowest priority < 0
				group.priority = product_priority

			for dependency in dependencies:
				if dependency.requiredProductId in dependencies_processed:
					logger.debug("Skipping dependency to product id already processed: %s", dependency.requiredProductId)
					continue
				dependencies_processed.append(dependency.requiredProductId)

				try:
					dep_product_on_depot = get_product_on_depot(
						depot_id=depot_id,
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

				dep_poc = get_product_on_client(
					product_id=dep_product.id, product_type=dep_product.getType(), client_id=product_on_client.clientId
				)
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
				dep_poc.actionRequest = required_action
				# dependency.requirementType None => after
				dep_group_idx = group_idx
				if dependency.requirementType != "before":
					dep_group_idx += 1
				add_product_on_client(
					product_action_groups=product_action_groups,
					product_on_client=dep_poc,
					group=group,
					group_idx=dep_group_idx,
					dependencies_processed=dependencies_processed,
				)

		for client_id, pocs in product_on_clients_by_client_id.items():
			for poc in pocs:
				add_product_on_client(product_action_groups[client_id], poc)
			product_action_groups[client_id].sort(key=lambda x: x.priority, reverse=True)

			action_sequence = 0
			for group in product_action_groups[client_id]:
				logger.trace(group)
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
