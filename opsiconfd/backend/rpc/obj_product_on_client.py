# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_on_client
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import ProductOnClient  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCProductOnClientMixin(Protocol):
	@rpc_method
	def productOnClient_insertObject(self: BackendProtocol, productOnClient: dict | ProductOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productOnClient_insertObject")
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True)

	@rpc_method
	def productOnClient_updateObject(self: BackendProtocol, productOnClient: dict | ProductOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("productOnClient_updateObject")
		self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=False, set_null=False)

	@rpc_method
	def productOnClient_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: List[dict] | List[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_createObjects")
		for productOnClient in forceList(productOnClients):
			self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=True)

	@rpc_method
	def productOnClient_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: List[dict] | List[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_updateObjects")
		for productOnClient in forceList(productOnClients):
			self._mysql.insert_object(table="PRODUCT_ON_CLIENT", obj=productOnClient, ace=ace, create=True, set_null=False)

	@rpc_method
	def productOnClient_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[ProductOnClient]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", ace=ace, object_type=ProductOnClient, attributes=attributes, filter=filter
		)

	@rpc_method
	def productOnClient_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def productOnClient_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("productOnClient_getObjects")
		return self._mysql.get_idents(table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def productOnClient_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productOnClients: List[dict] | List[ProductOnClient] | dict | ProductOnClient
	) -> None:
		ace = self._get_ace("productOnClient_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_ON_CLIENT", object_type=ProductOnClient, obj=productOnClients, ace=ace)

	@rpc_method
	def productOnClient_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.productOnClient_deleteObjects([{"id": id}])
