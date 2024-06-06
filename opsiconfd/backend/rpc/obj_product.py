# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.product_dependency
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import Product
from opsicommon.types import forceList, forceObjectClass

from ..mysql.cleanup import (
	remove_orphans_object_to_group_product,
	remove_orphans_product_on_client,
	remove_orphans_product_property_state,
	remove_orphans_windows_software_id_to_product,
)
from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductMixin(Protocol):
	def product_bulkInsertObjects(self: BackendProtocol, products: list[dict] | list[Product]) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT", objs=products)  # type: ignore[arg-type]

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_insertObject(self: BackendProtocol, product: dict | Product) -> None:
		ace = self._get_ace("product_insertObject")
		product = forceObjectClass(product, Product)
		self._mysql.insert_object(table="PRODUCT", obj=product, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_updateObject(self: BackendProtocol, product: dict | Product) -> None:
		ace = self._get_ace("product_updateObject")
		product = forceObjectClass(product, Product)
		self._mysql.insert_object(table="PRODUCT", obj=product, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_createObjects(self: BackendProtocol, products: list[dict] | list[Product] | dict | Product) -> None:
		ace = self._get_ace("product_createObjects")
		with self._mysql.session() as session:
			for product in forceList(products):
				product = forceObjectClass(product, Product)
				self._mysql.insert_object(table="PRODUCT", obj=product, ace=ace, create=True, set_null=True, session=session)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_updateObjects(self: BackendProtocol, products: list[dict] | list[Product] | dict | Product) -> None:
		ace = self._get_ace("product_updateObjects")
		with self._mysql.session() as session:
			for product in forceList(products):
				product = forceObjectClass(product, Product)
				self._mysql.insert_object(table="PRODUCT", obj=product, ace=ace, create=True, set_null=False, session=session)

	@rpc_method(check_acl=False)
	def product_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[Product]:
		ace = self._get_ace("product_getObjects")
		return self._mysql.get_objects(table="PRODUCT", ace=ace, object_type=Product, attributes=attributes, filter=filter)

	@rpc_method(deprecated=True, alternative_method="product_getObjects", check_acl=False)
	def product_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("product_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT", object_type=Product, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def product_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("product_getObjects")
		return self._mysql.get_idents(table="PRODUCT", object_type=Product, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_deleteObjects(self: BackendProtocol, products: list[dict] | list[Product] | dict | Product) -> None:
		if not products:
			return
		ace = self._get_ace("product_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT", object_type=Product, obj=products, ace=ace)
		with self._mysql.session() as session:
			remove_orphans_object_to_group_product(session)
			remove_orphans_product_on_client(session)
			remove_orphans_product_property_state(session)
			remove_orphans_windows_software_id_to_product(session)

	@rpc_method(check_acl=False)
	def product_delete(self: BackendProtocol, id: list[str] | str) -> None:
		idents = self.product_getIdents(returnType="dict", id=id)
		if idents:
			self.product_deleteObjects(idents)
