# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.product_on_depot
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import ProductOnDepot
from opsicommon.types import forceList, forceObjectClass

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductOnDepotMixin(Protocol):
	def productOnDepot_bulkInsertObjects(self: BackendProtocol, productOnDepots: list[dict] | list[ProductOnDepot]) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_ON_DEPOT", objs=productOnDepots)  # type: ignore[arg-type]

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productOnDepot_insertObject(self: BackendProtocol, productOnDepot: dict | ProductOnDepot) -> None:
		ace = self._get_ace("productOnDepot_insertObject")
		productOnDepot = forceObjectClass(productOnDepot, ProductOnDepot)
		self._mysql.insert_object(table="PRODUCT_ON_DEPOT", obj=productOnDepot, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productOnDepot_updateObject(self: BackendProtocol, productOnDepot: dict | ProductOnDepot) -> None:
		ace = self._get_ace("productOnDepot_updateObject")
		productOnDepot = forceObjectClass(productOnDepot, ProductOnDepot)
		self._mysql.insert_object(table="PRODUCT_ON_DEPOT", obj=productOnDepot, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productOnDepot_createObjects(
		self: BackendProtocol, productOnDepots: list[dict] | list[ProductOnDepot] | dict | ProductOnDepot
	) -> None:
		ace = self._get_ace("productOnDepot_createObjects")
		with self._mysql.session() as session:
			for productOnDepot in forceList(productOnDepots):
				productOnDepot = forceObjectClass(productOnDepot, ProductOnDepot)
				self._mysql.insert_object(
					table="PRODUCT_ON_DEPOT", obj=productOnDepot, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productOnDepot_create(
		self: BackendProtocol,
		productId: str,
		productType: str,
		productVersion: str,
		packageVersion: str,
		depotId: str,
		locked: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productOnDepot_createObjects(ProductOnDepot.fromHash(_hash))

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productOnDepot_updateObjects(
		self: BackendProtocol, productOnDepots: list[dict] | list[ProductOnDepot] | dict | ProductOnDepot
	) -> None:
		ace = self._get_ace("productOnDepot_updateObjects")
		with self._mysql.session() as session:
			for productOnDepot in forceList(productOnDepots):
				productOnDepot = forceObjectClass(productOnDepot, ProductOnDepot)
				self._mysql.insert_object(
					table="PRODUCT_ON_DEPOT", obj=productOnDepot, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def productOnDepot_getObjects(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[ProductOnDepot]:
		ace = self._get_ace("productOnDepot_getObjects")
		return self._mysql.get_objects(table="PRODUCT_ON_DEPOT", ace=ace, object_type=ProductOnDepot, attributes=attributes, filter=filter)

	@rpc_method(deprecated=True, alternative_method="productOnDepot_getObjects", check_acl=False)
	def productOnDepot_getHashes(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[dict]:
		ace = self._get_ace("productOnDepot_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_DEPOT", object_type=ProductOnDepot, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productOnDepot_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productOnDepot_getObjects")
		return self._mysql.get_idents(table="PRODUCT_ON_DEPOT", object_type=ProductOnDepot, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productOnDepot_deleteObjects(
		self: BackendProtocol, productOnDepots: list[dict] | list[ProductOnDepot] | dict | ProductOnDepot
	) -> None:
		if not productOnDepots:
			return
		ace = self._get_ace("productOnDepot_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_ON_DEPOT", object_type=ProductOnDepot, obj=productOnDepots, ace=ace)

	@rpc_method(check_acl=False)
	def productOnDepot_delete(
		self: BackendProtocol,
		productId: list[str] | str,
		depotId: list[str] | str,
		productType: list[str] | str | None = None,
		productVersion: list[str] | str | None = None,
		packageVersion: list[str] | str | None = None,
	) -> None:
		if productType is None:
			productType = []
		if productVersion is None:
			productVersion = []
		if packageVersion is None:
			packageVersion = []
		idents = self.productOnDepot_getIdents(
			returnType="dict",
			productId=productId,
			productType=productType,
			productVersion=productVersion,
			packageVersion=packageVersion,
			depotId=depotId,
		)
		if idents:
			self.productOnDepot_deleteObjects(idents)
