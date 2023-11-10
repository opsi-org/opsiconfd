# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_property_state
"""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import ProductPropertyState  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceList,
	forceObjectClass,
	forceObjectIdList,
	forceUnicodeList,
)

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductPropertyStateMixin(Protocol):
	def _get_product_property_state_values_with_defaults(
		self: BackendProtocol, product_property_ids: list[str], object_id: str
	) -> dict[str, list[Any]]:
		res: dict[str, list[Any]] = {
			product_property.id: product_property.defaultValues
			for product_property in self.productProperty_getObjects(id=product_property_ids)
		}
		res.update(
			{
				product_property_state.productPropertyId: product_property_state.values
				for product_property_state in self.productPropertyState_getObjects(
					product_propertyId=product_property_ids, objectId=object_id
				)
			}
		)
		return res

	@rpc_method(check_acl=False)
	def productPropertyState_getValues(  # pylint: disable=invalid-name
		self: BackendProtocol,
		product_ids: list[str] | str | None = None,
		property_ids: list[str] | str | None = None,
		object_ids: list[str] | str | None = None,
		with_defaults: bool = True,
	) -> dict[str, dict[str, dict[str, list[Any]]]]:
		product_ids = forceUnicodeList(product_ids or [])
		property_ids = forceUnicodeList(property_ids or [])
		object_ids = forceObjectIdList(object_ids or [])

		res: dict[str, dict[str, dict[str, list[Any]]]] = {}
		if with_defaults:
			client_id_to_depot_id = {
				ctd["clientId"]: ctd["depotId"] for ctd in self.configState_getClientToDepotserver(clientIds=object_ids, masterOnly=True)
			}
			depot_values: dict[str, dict[str, dict[str, list[Any]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
			depot_ids = list(set(client_id_to_depot_id.values()))
			if depot_ids:
				for pps in self.productPropertyState_getObjects(productId=product_ids, propertyId=property_ids, objectId=depot_ids):
					depot_values[pps.objectId][pps.productId][pps.propertyId] = pps.values

			for host_id in self.host_getIdents(returnType="str", id=object_ids):
				res[host_id] = {}
				depot_id = client_id_to_depot_id.get(host_id)
				if depot_id and depot_id in depot_values:
					res[host_id] = depot_values[depot_id].copy()

		for pps in self.productPropertyState_getObjects(productId=product_ids, propertyId=property_ids, objectId=object_ids):
			if pps.objectId not in res:
				res[pps.objectId] = {}
			if pps.productId not in res[pps.objectId]:
				res[pps.objectId][pps.productId] = {}
			res[pps.objectId][pps.productId][pps.propertyId] = pps.values

		return res

	def productPropertyState_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		productPropertyStates: list[dict] | list[ProductPropertyState],  # pylint: disable=invalid-name
	) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_PROPERTY_STATE", objs=productPropertyStates)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def productPropertyState_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol,
		productPropertyState: dict | ProductPropertyState,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productPropertyState_insertObject")
		productPropertyState = forceObjectClass(productPropertyState, ProductPropertyState)
		self._mysql.insert_object(table="PRODUCT_PROPERTY_STATE", obj=productPropertyState, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def productPropertyState_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol,
		productPropertyState: dict | ProductPropertyState,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productPropertyState_updateObject")
		productPropertyState = forceObjectClass(productPropertyState, ProductPropertyState)
		self._mysql.insert_object(table="PRODUCT_PROPERTY_STATE", obj=productPropertyState, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def productPropertyState_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productPropertyStates: list[dict] | list[ProductPropertyState] | dict | ProductPropertyState
	) -> None:
		ace = self._get_ace("productPropertyState_createObjects")
		with self._mysql.session() as session:
			for product_property_state in forceList(productPropertyStates):
				product_property_state = forceObjectClass(product_property_state, ProductPropertyState)
				self._mysql.insert_object(
					table="PRODUCT_PROPERTY_STATE", obj=product_property_state, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False)
	def productPropertyState_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		productPropertyStates: list[dict] | list[ProductPropertyState] | dict | ProductPropertyState,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productPropertyState_updateObjects")
		with self._mysql.session() as session:
			for product_property_state in forceList(productPropertyStates):
				product_property_state = forceObjectClass(product_property_state, ProductPropertyState)
				self._mysql.insert_object(
					table="PRODUCT_PROPERTY_STATE", obj=product_property_state, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def productPropertyState_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,  # pylint: disable=redefined-builtin
	) -> list[ProductPropertyState]:
		ace = self._get_ace("productPropertyState_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_PROPERTY_STATE", ace=ace, object_type=ProductPropertyState, attributes=attributes, filter=filter
		)

	@rpc_method(deprecated=True, alternative_method="productPropertyState_getObjects", check_acl=False)
	def productPropertyState_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ace = self._get_ace("productPropertyState_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_PROPERTY_STATE",
			object_type=ProductPropertyState,
			ace=ace,
			return_type="dict",
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def productPropertyState_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productPropertyState_getObjects")
		return self._mysql.get_idents(
			table="PRODUCT_PROPERTY_STATE", object_type=ProductPropertyState, ace=ace, ident_type=returnType, filter=filter
		)

	@rpc_method(check_acl=False)
	def productPropertyState_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productPropertyStates: list[dict] | list[ProductPropertyState] | dict | ProductPropertyState
	) -> None:
		if not productPropertyStates:
			return
		ace = self._get_ace("productPropertyState_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_PROPERTY_STATE", object_type=ProductPropertyState, obj=productPropertyStates, ace=ace)

	@rpc_method(check_acl=False)
	def productPropertyState_create(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, propertyId: str, objectId: str, values: list[Any] | None = None
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productPropertyState_createObjects(ProductPropertyState.fromHash(_hash))

	@rpc_method(check_acl=False)
	def productPropertyState_delete(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: list[str] | str, propertyId: list[str] | str, objectId: list[str] | str
	) -> None:
		idents = self.productPropertyState_getIdents(returnType="dict", productId=productId, propertyId=propertyId, objectId=objectId)
		if idents:
			self.productPropertyState_deleteObjects(idents)
