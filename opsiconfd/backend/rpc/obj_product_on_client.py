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
from typing import TYPE_CHECKING, Any, Callable, List, Protocol

from OPSI.SharedAlgorithm import (  # type: ignore[import]
	addDependentProductOnClients,
	generateProductOnClientSequence_algorithm1,
)
from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.objects import (  # type: ignore[import]
	Product,
	ProductDependency,
	ProductOnClient,
)
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductOnClientMixin(Protocol):
	@rpc_method(check_acl=False)
	def productOnClient_insertObject(self: BackendProtocol, productOnClient: dict | ProductOnClient) -> None:  # pylint: disable=invalid-name
		self._check_module("mysql_backend")
		ace = self._get_ace("productOnClient_insertObject")
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def productOnClient_updateObject(self: BackendProtocol, productOnClient: dict | ProductOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productOnClient_updateObject")
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def productOnClient_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: List[dict] | List[ProductOnClient] | dict | ProductOnClient
	) -> None:
		self._check_module("mysql_backend")
		ace = self._get_ace("productOnClient_createObjects")
		for productOnClient in forceList(productOnClients):
			self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def productOnClient_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: List[dict] | List[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_updateObjects")
		for productOnClient in forceList(productOnClients):
			self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=False)

	@rpc_method(check_acl=False)
	def productOnClient_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[ProductOnClient]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", ace=ace, object_type=ProductOnClient, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productOnClient_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productOnClient_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_idents(table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def productOnClient_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: List[dict] | List[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, obj=productOnClients, ace=ace)

	@rpc_method(check_acl=False)
	def productOnClient_create(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		productId: str,  # pylint: disable=unused-argument
		productType: str,  # pylint: disable=unused-argument
		clientId: str,  # pylint: disable=unused-argument
		installationStatus: str = None,  # pylint: disable=unused-argument
		actionRequest: str = None,  # pylint: disable=unused-argument
		lastAction: str = None,  # pylint: disable=unused-argument
		actionProgress: str = None,  # pylint: disable=unused-argument
		actionResult: str = None,  # pylint: disable=unused-argument
		productVersion: str = None,  # pylint: disable=unused-argument
		packageVersion: str = None,  # pylint: disable=unused-argument
		modificationTime: str = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productOnClient_createObjects(ProductOnClient.fromHash(_hash))

	@rpc_method(check_acl=False)
	def productOnClient_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.productOnClient_deleteObjects([{"id": id}])

	def _product_on_client_process_with_function(  # pylint: disable=too-many-locals,too-many-branches
		self: BackendProtocol, product_on_clients: List[ProductOnClient], function: Callable
	) -> List[ProductOnClient]:
		product_on_clients_by_client: dict[str, list[ProductOnClient]] = {}
		product_ids = set()
		for poc in product_on_clients:
			try:  # pylint: disable=loop-try-except-usage
				product_on_clients_by_client[poc.getClientId()].append(poc)
			except KeyError:
				product_on_clients_by_client[poc.getClientId()] = [poc]

			product_ids.add(poc.productId)

		depot_to_clients: dict[str, list[str]] = {}
		for client_to_depot in self.configState_getClientToDepotserver(clientIds=(clientId for clientId in product_on_clients_by_client)):
			try:  # pylint: disable=loop-try-except-usage
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
			p_deps_by_product_id_and_version: dict[str, dict[str, dict[str, list[ProductDependency]]]]
		) -> None:
			p_deps_by_product_id_and_version[product_dependency.productId][product_dependency.productVersion][
				product_dependency.packageVersion
			].append(
				product_dependency
			)

			if product_dependency.requiredProductId not in product_ids and product_dependency.requiredProductId not in additional_product_ids:
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
			p_deps_by_product_id_and_version: dict[str, dict[str, dict[str, list[ProductDependency]]]]
		) -> None:
			dependencies = p_deps_by_product_id_and_version[product.id][product.productVersion][product.packageVersion]
			for dep in dependencies:
				product = product_by_product_id_and_version[dep.productId][dep.productVersion][dep.packageVersion]
				if product:
					products.add(product)
					if dep not in product_dependencies:
						product_dependencies.add(dep)
						add_dependencies(product, products, product_dependencies, product_by_product_id_and_version, p_deps_by_product_id_and_version)

		product_on_clients = []
		for (depot_id, client_ids) in depot_to_clients.items():
			products: set[Product] = set()  # pylint: disable=loop-invariant-statement
			product_dependencies: set[ProductDependency] = set()  # pylint: disable=loop-invariant-statement

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
				add_dependencies(product, products, product_dependencies, product_by_product_id_and_version, p_deps_by_product_id_and_version)

			for client_id in client_ids:
				try:  # pylint: disable=loop-try-except-usage
					product_on_clients_by_client[client_id]
				except KeyError:
					continue

				product_on_clients.extend(
					function(
						productOnClients=product_on_clients_by_client[client_id],
						availableProducts=products,
						productDependencies=product_dependencies,
					)
				)

		return product_on_clients

	@rpc_method(check_acl=False)
	def productOnClient_generateSequence(self: BackendProtocol, productOnClients: List[ProductOnClient]) -> List[ProductOnClient]:  # pylint: disable=invalid-name
		return self._product_on_client_process_with_function(productOnClients, generateProductOnClientSequence_algorithm1)

	@rpc_method(check_acl=False)
	def productOnClient_addDependencies(self: BackendProtocol, productOnClients: List[ProductOnClient]) -> List[ProductOnClient]:  # pylint: disable=invalid-name
		return self._product_on_client_process_with_function(productOnClients, addDependentProductOnClients)
