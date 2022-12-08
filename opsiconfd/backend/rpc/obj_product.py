# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_dependency
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import Product  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

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
	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_insertObject(self: BackendProtocol, product: dict | Product) -> None:  # pylint: disable=invalid-name
		self._check_module("mysql_backend")
		ace = self._get_ace("product_insertObject")
		self._mysql.insert_object(table="PRODUCT", obj=product, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_updateObject(self: BackendProtocol, product: dict | Product) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("product_updateObject")
		self._mysql.insert_object(table="PRODUCT", obj=product, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, products: List[dict] | List[Product] | dict | Product
	) -> None:
		self._check_module("mysql_backend")
		ace = self._get_ace("product_createObjects")
		for product in forceList(products):
			self._mysql.insert_object(table="PRODUCT", obj=product, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, products: List[dict] | List[Product] | dict | Product
	) -> None:
		ace = self._get_ace("product_updateObjects")
		for product in forceList(products):
			self._mysql.insert_object(table="PRODUCT", obj=product, ace=ace, create=True, set_null=False)

	@rpc_method(check_acl=False)
	def product_getObjects(self: BackendProtocol, attributes: List[str] | None = None, **filter: Any) -> List[Product]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("product_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT", ace=ace, object_type=Product, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def product_getHashes(self: BackendProtocol, attributes: List[str] | None = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("product_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT", object_type=Product, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def product_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("product_getObjects")
		return self._mysql.get_idents(table="PRODUCT", object_type=Product, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def product_deleteObjects(self: BackendProtocol, products: List[dict] | List[Product] | dict | Product) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("product_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT", object_type=Product, obj=products, ace=ace)
		with self._mysql.session() as session:
			remove_orphans_object_to_group_product(session)
			remove_orphans_product_on_client(session)
			remove_orphans_product_property_state(session)
			remove_orphans_windows_software_id_to_product(session)

	@rpc_method(check_acl=False)
	def product_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.product_deleteObjects([{"id": id}])
