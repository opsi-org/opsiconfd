# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_property_state
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Protocol

from opsicommon.objects import ProductPropertyState  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

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
	def productPropertyState_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.productProperty_deleteObjects([{"id": id}])
