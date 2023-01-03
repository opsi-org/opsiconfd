# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_property
"""
from __future__ import annotations

from contextlib import nullcontext
from typing import TYPE_CHECKING, Any, Literal, Protocol

from opsicommon.objects import ProductProperty  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from ..auth import RPCACE
from ..mysql.cleanup import remove_orphans_product_property_state
from . import rpc_method

if TYPE_CHECKING:
	from ..mysql import Session
	from .protocol import BackendProtocol, IdentType


class RPCProductPropertyMixin(Protocol):
	def _product_property_insert_object(  # pylint: disable=too-many-arguments
		self: BackendProtocol,
		product_property: ProductProperty | dict,
		ace: list[RPCACE],
		create: bool = True,
		set_null: bool = True,
		session: Session | None = None,
		lock: bool = True
	) -> None:
		query, data = self._mysql.insert_query(table="PRODUCT_PROPERTY", obj=product_property, ace=ace, create=create, set_null=set_null)
		with self._mysql.session(session) as session:  # pylint: disable=redefined-argument-from-local
			with self._mysql.table_lock(session, {"PRODUCT_PROPERTY": "WRITE", "PRODUCT_PROPERTY_VALUE": "WRITE"}) if lock else nullcontext():
				session.execute(
					"""
					DELETE FROM `PRODUCT_PROPERTY_VALUE`
					WHERE productId = :productId AND productVersion = :productVersion AND packageVersion = :packageVersion AND propertyId = :propertyId
					""",
					params=data
				)
				if session.execute(query, params=data).rowcount > 0:
					for value in data["possibleValues"] or []:
						session.execute(
							"""
							INSERT INTO `PRODUCT_PROPERTY_VALUE`
								(productId, productVersion, packageVersion, propertyId, value, isDefault)
							VALUES
								(:productId, :productVersion, :packageVersion, :propertyId, :value, :isDefault)
							""",
							params={
								"productId": data["productId"],  # pylint: disable=loop-invariant-statement
								"productVersion": data["productVersion"],  # pylint: disable=loop-invariant-statement
								"packageVersion": data["packageVersion"],  # pylint: disable=loop-invariant-statement
								"propertyId": data["propertyId"],  # pylint: disable=loop-invariant-statement
								"value": value,
								"isDefault": value in (data["defaultValues"] or [])  # pylint: disable=loop-invariant-statement
							}
						)

	@rpc_method(check_acl=False)
	def productProperty_insertObject(self: BackendProtocol, productProperty: dict | ProductProperty) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productProperty_insertObject")
		self._product_property_insert_object(product_property=productProperty, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def productProperty_updateObject(self: BackendProtocol, productProperty: dict | ProductProperty) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productProperty_updateObject")
		self._product_property_insert_object(product_property=productProperty, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def productProperty_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productProperties: list[dict] | list[ProductProperty] | dict | ProductProperty
	) -> None:
		ace = self._get_ace("productProperty_createObjects")
		with self._mysql.session() as session:
			with self._mysql.table_lock(session, {"PRODUCT_PROPERTY": "WRITE", "PRODUCT_PROPERTY_VALUE": "WRITE"}):
				for product_property in forceList(productProperties):
					self._product_property_insert_object(
						product_property=product_property, ace=ace, create=True, set_null=True, session=session, lock=False
					)

	@rpc_method(check_acl=False)
	def productProperty_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productProperties: list[dict] | list[ProductProperty] | dict | ProductProperty
	) -> None:
		ace = self._get_ace("productProperty_updateObjects")
		with self._mysql.session() as session:
			with self._mysql.table_lock(session, {"PRODUCT_PROPERTY": "WRITE", "PRODUCT_PROPERTY_VALUE": "WRITE"}):
				for product_property in forceList(productProperties):
					self._product_property_insert_object(
						product_property=product_property, ace=ace, create=True, set_null=False, session=session, lock=False
					)

	def _product_property_get(  # pylint: disable=too-many-arguments,too-many-locals
		self: BackendProtocol,
		ace: list[RPCACE] | None = None,
		return_type: Literal["object", "dict"] = "object",
		attributes: list[str] | tuple[str, ...] | None = None,
		filter: dict[str, Any] | None = None,  # pylint: disable=redefined-builtin
	) -> list[dict] | list[ProductProperty]:
		aggregates = {
			"possibleValues": f'GROUP_CONCAT(`value` SEPARATOR "{self._mysql.record_separator}")',
			"defaultValues": f'GROUP_CONCAT(IF(`isDefault`, `value`, NULL) SEPARATOR "{self._mysql.record_separator}")'
		}
		return self._mysql.get_objects(
			table=(
				"`PRODUCT_PROPERTY` LEFT JOIN `PRODUCT_PROPERTY_VALUE` ON "
				"`PRODUCT_PROPERTY`.`productId` = `PRODUCT_PROPERTY_VALUE`.`productId` AND "
				"`PRODUCT_PROPERTY`.`productVersion` = `PRODUCT_PROPERTY_VALUE`.`productVersion` AND "
				"`PRODUCT_PROPERTY`.`packageVersion` = `PRODUCT_PROPERTY_VALUE`.`packageVersion` AND "
				"`PRODUCT_PROPERTY`.`propertyId` = `PRODUCT_PROPERTY_VALUE`.`propertyId`"
			),
			object_type=ProductProperty,
			aggregates=aggregates,
			ace=ace,
			return_type=return_type,
			attributes=attributes,
			filter=filter
		)

	@rpc_method(check_acl=False)
	def productProperty_getObjects(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[ProductProperty]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productProperty_getObjects")
		return self._product_property_get(ace=ace, return_type="object", attributes=attributes, filter=filter)  # type: ignore[return-value]

	@rpc_method(check_acl=False)
	def productProperty_getHashes(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productProperty_getObjects")
		return self._product_property_get(ace=ace, return_type="dict", attributes=attributes, filter=filter)  # type: ignore[return-value]

	@rpc_method(check_acl=False)
	def productProperty_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productProperty_getObjects")
		return self._mysql.get_idents("PRODUCT_PROPERTY", ProductProperty, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def productProperty_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productProperties: list[dict] | list[ProductProperty] | dict | ProductProperty
	) -> None:
		# PRODUCT_PROPERTY_VALUE will be deleted by CASCADE
		ace = self._get_ace("productProperty_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_PROPERTY", object_type=ProductProperty, obj=productProperties, ace=ace)
		with self._mysql.session() as session:
			remove_orphans_product_property_state(session)

	@rpc_method(check_acl=False)
	def productProperty_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.productProperty_deleteObjects([{"id": id}])
