# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_dependency
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import ProductDependency  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductDependencyMixin(Protocol):
	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_insertObject(self: BackendProtocol, productDependency: dict | ProductDependency) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productDependency_insertObject")
		if isinstance(productDependency, dict):
			productDependency["type"] = "ProductDependency"
		self._mysql.insert_object(table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_updateObject(self: BackendProtocol, productDependency: dict | ProductDependency) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productDependency_updateObject")
		if isinstance(productDependency, dict):
			productDependency["type"] = "ProductDependency"
		self._mysql.insert_object(table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency
	) -> None:
		ace = self._get_ace("productDependency_createObjects")
		with self._mysql.session() as session:
			for productDependency in forceList(productDependencies):
				if isinstance(productDependency, dict):
					productDependency["type"] = "ProductDependency"
				self._mysql.insert_object(table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=True, session=session)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency
	) -> None:
		ace = self._get_ace("productDependency_updateObjects")
		with self._mysql.session() as session:
			for productDependency in forceList(productDependencies):
				if isinstance(productDependency, dict):
					productDependency["type"] = "ProductDependency"
				self._mysql.insert_object(table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=False, session=session)

	@rpc_method(check_acl=False)
	def productDependency_getObjects(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[ProductDependency]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_DEPENDENCY", ace=ace, object_type=ProductDependency, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productDependency_getHashes(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_DEPENDENCY", object_type=ProductDependency, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productDependency_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_idents(table="PRODUCT_DEPENDENCY", object_type=ProductDependency, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency
	) -> None:
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
		productId: str,
		productVersion: str,
		packageVersion: str,
		productAction: str,
		requiredProductId: str
	) -> None:
		self.productDependency_deleteObjects(
			[
				{
					"productId": productId,
					"productVersion": productVersion,
					"packageVersion": packageVersion,
					"productAction": productAction,
					"requiredProductId": requiredProductId
				}
			]
		)
