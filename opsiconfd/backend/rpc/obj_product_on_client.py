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

from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.objects import (  # type: ignore[import]
	Product,
	ProductDependency,
	ProductOnClient,
)
from opsicommon.types import (  # type: ignore[import]
	forceList,
	forceObjectClass,
	forceObjectClassList,
)

from . import rpc_method
from .obj_product_dependency import (
	add_dependent_product_on_clients,
	generate_product_on_client_sequence,
)

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
		with self._mysql.session() as session:
			for productOnClient in forceList(productOnClients):
				productOnClient = forceObjectClass(productOnClient, ProductOnClient)
				self._mysql.insert_object(
					table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True, session=session
				)
				if self.events_enabled:
					self._send_messagebus_event("productOnClient_created", data=productOnClient.getIdent("dict"))  # type: ignore[arg-type]
		if not self.events_enabled:
			return
		self.opsipxeconfd_product_on_clients_updated(productOnClients)

	@rpc_method(check_acl=False)
	def productOnClient_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_updateObjects")
		with self._mysql.session() as session:
			for productOnClient in forceList(productOnClients):
				productOnClient = forceObjectClass(productOnClient, ProductOnClient)
				self._mysql.insert_object(
					table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=False, session=session
				)
				if self.events_enabled:
					self._send_messagebus_event("productOnClient_updated", data=productOnClient.getIdent("dict"))  # type: ignore[arg-type]
		if not self.events_enabled:
			return
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
		self: BackendProtocol, productId: str, productType: str, clientId: str
	) -> None:
		idents = self.productOnClient_getIdents(returnType="dict", productId=productId, productType=productType, clientId=clientId)
		if idents:
			self.productOnClient_deleteObjects(idents)

	def _product_on_client_process_with_function(  # pylint: disable=too-many-locals,too-many-branches
		self: BackendProtocol, product_on_clients: list[ProductOnClient], function: Callable
	) -> list[ProductOnClient]:
		product_on_clients_by_client: dict[str, list[ProductOnClient]] = {}
		product_ids = set()
		for poc in product_on_clients:
			poc = forceObjectClass(poc, ProductOnClient)
			try:
				product_on_clients_by_client[poc.getClientId()].append(poc)
			except KeyError:
				product_on_clients_by_client[poc.getClientId()] = [poc]

			product_ids.add(poc.productId)

		depot_to_clients: dict[str, list[str]] = {}
		for client_to_depot in self.configState_getClientToDepotserver(clientIds=(clientId for clientId in product_on_clients_by_client)):
			try:
				depot_to_clients[client_to_depot["depotId"]].append(client_to_depot["clientId"])
			except KeyError:
				depot_to_clients[client_to_depot["depotId"]] = [client_to_depot["clientId"]]

		product_by_product_id_and_version: dict[str, dict[str, dict[str, Product]]] = defaultdict(lambda: defaultdict(dict))
		for product in self.product_getObjects(id=product_ids):
			product_by_product_id_and_version[product.id][product.productVersion][product.packageVersion] = product

		additional_product_ids: list[str] = []
		p_deps_by_product_id_and_version: dict[str, dict[str, dict[str, list[ProductDependency]]]] = defaultdict(
			lambda: defaultdict(lambda: defaultdict(list))
		)

		def collect_dependencies(
			additional_product_ids: list[str],
			product_dependency: ProductDependency,
			p_deps_by_product_id_and_version: dict[str, dict[str, dict[str, list[ProductDependency]]]],
		) -> None:
			p_deps_by_product_id_and_version[product_dependency.productId][product_dependency.productVersion][
				product_dependency.packageVersion
			].append(product_dependency)

			if (
				product_dependency.requiredProductId not in product_ids
				and product_dependency.requiredProductId not in additional_product_ids
			):
				additional_product_ids.append(product_dependency.requiredProductId)
				for product_dependency_2 in self.productDependency_getObjects(productId=product_dependency.requiredProductId):
					collect_dependencies(additional_product_ids, product_dependency_2, p_deps_by_product_id_and_version)

		for product_dependency in self.productDependency_getObjects(productId=product_ids):
			collect_dependencies(additional_product_ids, product_dependency, p_deps_by_product_id_and_version)

		if additional_product_ids:
			for product in self.product_getObjects(id=additional_product_ids):
				product_by_product_id_and_version[product.id][product.productVersion][product.packageVersion] = product

			product_ids = product_ids.union(additional_product_ids)

		def add_dependencies(
			product: Product,
			products: set[Product],
			product_dependencies: set[ProductDependency],
			product_by_product_id_and_version: dict[str, dict[str, dict[str, Product]]],
			p_deps_by_product_id_and_version: dict[str, dict[str, dict[str, list[ProductDependency]]]],
		) -> None:
			dependencies = p_deps_by_product_id_and_version[product.id][product.productVersion][product.packageVersion]
			for dep in dependencies:
				product = product_by_product_id_and_version[dep.productId][dep.productVersion][dep.packageVersion]
				if product:
					products.add(product)
					if dep not in product_dependencies:
						product_dependencies.add(dep)
						add_dependencies(
							product, products, product_dependencies, product_by_product_id_and_version, p_deps_by_product_id_and_version
						)

		product_on_clients = []
		for (depot_id, client_ids) in depot_to_clients.items():
			products: set[Product] = set()
			product_dependencies: set[ProductDependency] = set()

			for product_on_depot in self.productOnDepot_getObjects(depotId=depot_id, productId=product_ids):
				product = product_by_product_id_and_version[product_on_depot.productId][product_on_depot.productVersion][
					product_on_depot.packageVersion
				]
				if product is None:
					raise BackendMissingDataError(
						f"Product '{product_on_depot.productId}', "
						f"productVersion '{product_on_depot.productVersion}', "
						f"packageVersion '{product_on_depot.packageVersion}' not found"
					)
				products.add(product)
				add_dependencies(
					product, products, product_dependencies, product_by_product_id_and_version, p_deps_by_product_id_and_version
				)

			for client_id in client_ids:
				try:
					product_on_clients_by_client[client_id]
				except KeyError:
					continue

				product_on_clients.extend(
					function(
						product_on_clients=product_on_clients_by_client[client_id],
						available_products=products,
						product_dependencies=product_dependencies,
					)
				)

		return product_on_clients

	@rpc_method(check_acl=False)
	def productOnClient_generateSequence(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: list[ProductOnClient]
	) -> list[ProductOnClient]:
		return self._product_on_client_process_with_function(productOnClients, generate_product_on_client_sequence)

	@rpc_method(check_acl=False)
	def productOnClient_addDependencies(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: list[ProductOnClient]
	) -> list[ProductOnClient]:
		productOnClients = self._product_on_client_process_with_function(productOnClients, add_dependent_product_on_clients)
		return self._product_on_client_process_with_function(productOnClients, generate_product_on_client_sequence)
