# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.product_property_state
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import ProductPropertyState
from opsicommon.types import (
	forceList,
	forceObjectClass,
	forceObjectIdList,
	forceUnicodeList,
)

from opsiconfd.backend.auth import RPCACE
from opsiconfd.config import get_configserver_id

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
	def productPropertyState_getValues(
		self: BackendProtocol,
		product_ids: list[str] | str | None = None,
		property_ids: list[str] | str | None = None,
		object_ids: list[str] | str | None = None,
		with_defaults: bool = True,
	) -> dict[str, dict[str, dict[str, list[Any]]]]:
		product_ids = forceUnicodeList(product_ids or [])
		property_ids = forceUnicodeList(property_ids or [])
		# object_ids can contain depot IDs!
		object_ids = forceObjectIdList(object_ids or [])
		if client_id := self._get_client_id():
			object_ids = [client_id]

		res: dict[str, dict[str, dict[str, list[Any]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
		if with_defaults:
			all_depot_ids = self.host_getIdents(returnType="str", type="OpsiDepotserver")
			client_ids = [object_id for object_id in object_ids if object_id not in all_depot_ids]
			configserver_id = get_configserver_id()

			if not object_ids or client_ids:
				client_id_to_depot_id = {
					ctd.objectId: (ctd.values or [None])[0]
					for ctd in self._configState_getObjects(objectId=client_ids, configId="clientconfig.depot.id")
				}
				depot_values: dict[str, dict[str, dict[str, list[Any]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
				depot_ids = list(set(client_id_to_depot_id.values()))
				if configserver_id not in depot_ids:
					depot_ids.append(configserver_id)
				if depot_ids:
					for pps in self._productPropertyState_getObjects(productId=product_ids, propertyId=property_ids, objectId=depot_ids):
						depot_values[pps.objectId][pps.productId][pps.propertyId] = pps.values or []

				for host_id in self.host_getIdents(returnType="str", type="OpsiClient", id=client_ids):
					res[host_id] = {}
					depot_id = client_id_to_depot_id.get(host_id) or configserver_id
					if depot_id in depot_values:
						res[host_id] = depot_values[depot_id].copy()

		for pps in self._productPropertyState_getObjects(productId=product_ids, propertyId=property_ids, objectId=object_ids):
			res[pps.objectId][pps.productId][pps.propertyId] = pps.values or []

		return res

	def productPropertyState_bulkInsertObjects(
		self: BackendProtocol,
		productPropertyStates: list[dict] | list[ProductPropertyState],
	) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_PROPERTY_STATE", objs=productPropertyStates)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def productPropertyState_insertObject(
		self: BackendProtocol,
		productPropertyState: dict | ProductPropertyState,
	) -> None:
		ace = self._get_ace("productPropertyState_insertObject")
		productPropertyState = forceObjectClass(productPropertyState, ProductPropertyState)
		self._mysql.insert_object(table="PRODUCT_PROPERTY_STATE", obj=productPropertyState, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def productPropertyState_updateObject(
		self: BackendProtocol,
		productPropertyState: dict | ProductPropertyState,
	) -> None:
		ace = self._get_ace("productPropertyState_updateObject")
		productPropertyState = forceObjectClass(productPropertyState, ProductPropertyState)
		self._mysql.insert_object(table="PRODUCT_PROPERTY_STATE", obj=productPropertyState, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def productPropertyState_createObjects(
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
	def productPropertyState_updateObjects(
		self: BackendProtocol,
		productPropertyStates: list[dict] | list[ProductPropertyState] | dict | ProductPropertyState,
	) -> None:
		ace = self._get_ace("productPropertyState_updateObjects")
		with self._mysql.session() as session:
			for product_property_state in forceList(productPropertyStates):
				product_property_state = forceObjectClass(product_property_state, ProductPropertyState)
				self._mysql.insert_object(
					table="PRODUCT_PROPERTY_STATE", obj=product_property_state, ace=ace, create=True, set_null=False, session=session
				)

	def _productPropertyState_getObjects(
		self: BackendProtocol,
		ace: list[RPCACE] | None = None,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[ProductPropertyState]:
		return self._mysql.get_objects(
			table="PRODUCT_PROPERTY_STATE", ace=ace or [], object_type=ProductPropertyState, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productPropertyState_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[ProductPropertyState]:
		return self._productPropertyState_getObjects(ace=self._get_ace("productPropertyState_getObjects"), attributes=attributes, **filter)

	@rpc_method(deprecated=True, alternative_method="productPropertyState_getObjects", check_acl=False)
	def productPropertyState_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
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
	def productPropertyState_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productPropertyState_getObjects")
		return self._mysql.get_idents(
			table="PRODUCT_PROPERTY_STATE", object_type=ProductPropertyState, ace=ace, ident_type=returnType, filter=filter
		)

	@rpc_method(check_acl=False)
	def productPropertyState_deleteObjects(
		self: BackendProtocol, productPropertyStates: list[dict] | list[ProductPropertyState] | dict | ProductPropertyState
	) -> None:
		if not productPropertyStates:
			return
		ace = self._get_ace("productPropertyState_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_PROPERTY_STATE", object_type=ProductPropertyState, obj=productPropertyStates, ace=ace)

	@rpc_method(check_acl=False)
	def productPropertyState_create(
		self: BackendProtocol, productId: str, propertyId: str, objectId: str, values: list[Any] | None = None
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productPropertyState_createObjects(ProductPropertyState.fromHash(_hash))

	@rpc_method(check_acl=False)
	def productPropertyState_delete(
		self: BackendProtocol, productId: list[str] | str, propertyId: list[str] | str, objectId: list[str] | str
	) -> None:
		idents = self.productPropertyState_getIdents(returnType="dict", productId=productId, propertyId=propertyId, objectId=objectId)
		if idents:
			self.productPropertyState_deleteObjects(idents)
