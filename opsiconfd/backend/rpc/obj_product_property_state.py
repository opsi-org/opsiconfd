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
from typing import TYPE_CHECKING, Any, Dict, List, Protocol

from opsicommon.objects import ProductPropertyState  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceList,
	forceObjectIdList,
	forceUnicodeList,
)

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductPropertyStateMixin(Protocol):
	def _get_product_property_state_values_with_defaults(
		self: BackendProtocol, product_property_ids: List[str], object_id: str
	) -> Dict[str, List[Any]]:
		res: Dict[str, List[Any]] = {
			product_property.id: product_property.defaultValues
			for product_property in self.productProperty_getObjects(id=product_property_ids)
		}
		res.update(
			{
				product_property_state.productPropertyId: product_property_state.values
				for product_property_state in self.productPropertyState_getObjects(product_propertyId=product_property_ids, objectId=object_id)
			}
		)
		return res

	@rpc_method
	def productPropertyState_getValues(  # pylint: disable=invalid-name
		self: BackendProtocol,
		product_ids: List[str] | str | None = None,
		property_ids: List[str] | str | None = None,
		object_ids: List[str] | str | None = None,
		with_defaults: bool = True
	) -> dict[str, dict[str, dict[str, list[Any]]]]:
		product_ids = forceUnicodeList(product_ids or [])
		property_ids = forceUnicodeList(property_ids or [])
		object_ids = forceObjectIdList(object_ids or [])

		res: dict[str, dict[str, dict[str, list[Any]]]] = {}
		if with_defaults:
			client_id_to_depot_id = {
				ctd["clientId"]: ctd["depotId"]
				for ctd in self.configState_getClientToDepotserver(clientIds=object_ids, masterOnly=True)
			}
			depot_values: dict[str, dict[str, dict[str, list[Any]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
			depot_ids = list(set(client_id_to_depot_id.values()))
			if depot_ids:
				for pps in self.productPropertyState_getObjects(
					productId=product_ids, propertyId=property_ids, objectId=depot_ids
				):
					depot_values[pps.objectId][pps.productId][pps.propertyId] = pps.values

			for host_id in self.host_getIdents(returnType="str", id=object_ids):
				res[host_id] = {}
				depot_id = client_id_to_depot_id.get(host_id)
				if depot_id and depot_id in depot_values:
					res[host_id] = depot_values[depot_id].copy()

		for pps in self.productPropertyState_getObjects(
			productId=product_ids, propertyId=property_ids, objectId=object_ids
		):
			if pps.objectId not in res:
				res[pps.objectId] = {}
			if pps.productId not in res[pps.objectId]:
				res[pps.objectId][pps.productId] = {}
			res[pps.objectId][pps.productId][pps.propertyId] = pps.values

		return res

	@rpc_method
	def productPropertyState_insertObject(self: BackendProtocol, productPropertyState: dict | ProductPropertyState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productPropertyState_insertObject")
		self._mysql.insert_object(table="PRODUCT_PROPERTY_STATE", obj=productPropertyState, ace=ace, create=True, set_null=True)

	@rpc_method
	def productPropertyState_updateObject(self: BackendProtocol, productPropertyState: dict | ProductPropertyState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productPropertyState_updateObject")
		self._mysql.insert_object(table="PRODUCT_PROPERTY_STATE", obj=productPropertyState, ace=ace, create=False, set_null=False)

	@rpc_method
	def productPropertyState_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productPropertyStates: List[dict] | List[ProductPropertyState] | dict | ProductPropertyState
	) -> None:
		ace = self._get_ace("productPropertyState_createObjects")
		for product_property_state in forceList(productPropertyStates):
			self._mysql.insert_object(table="PRODUCT_PROPERTY_STATE", obj=product_property_state, ace=ace, create=True, set_null=True)

	@rpc_method
	def productPropertyState_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productPropertyStates: List[dict] | List[ProductPropertyState] | dict | ProductPropertyState
	) -> None:
		ace = self._get_ace("productPropertyState_updateObjects")
		for product_property_state in forceList(productPropertyStates):
			self._mysql.insert_object(table="PRODUCT_PROPERTY_STATE", obj=product_property_state, ace=ace, create=True, set_null=False)

	@rpc_method
	def productPropertyState_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[ProductPropertyState]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productPropertyState_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_PROPERTY_STATE", ace=ace, object_type=ProductPropertyState, attributes=attributes, filter=filter
		)

	@rpc_method
	def productPropertyState_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productPropertyState_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_PROPERTY_STATE", object_type=ProductPropertyState, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def productPropertyState_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("productPropertyState_getObjects")
		return self._mysql.get_idents(
			table="PRODUCT_PROPERTY_STATE", object_type=ProductPropertyState, ace=ace, ident_type=returnType, filter=filter
		)

	@rpc_method
	def productPropertyState_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productPropertyStates: List[dict] | List[ProductPropertyState] | dict | ProductPropertyState
	) -> None:
		ace = self._get_ace("productPropertyState_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_PROPERTY_STATE", object_type=ProductPropertyState, obj=productPropertyStates, ace=ace)

	@rpc_method
	def productPropertyState_create(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, propertyId: str, objectId: str, values: list[Any] = None
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productPropertyState_createObjects(ProductPropertyState.fromHash(_hash))

	@rpc_method
	def productPropertyState_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.productProperty_deleteObjects([{"id": id}])
