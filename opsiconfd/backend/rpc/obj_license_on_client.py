# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.license_on_client
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import LicenseOnClient  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCLicenseOnClientMixin(Protocol):
	@rpc_method
	def licenseOnClient_insertObject(self: BackendProtocol, licenseOnClient: dict | LicenseOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("licenseOnClient_insertObject")
		self._mysql.insert_object(table="LICENSE_ON_CLIENT", obj=licenseOnClient, ace=ace, create=True, set_null=True)

	@rpc_method
	def licenseOnClient_updateObject(self: BackendProtocol, licenseOnClient: dict | LicenseOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("licenseOnClient_updateObject")
		self._mysql.insert_object(table="LICENSE_ON_CLIENT", obj=licenseOnClient, ace=ace, create=False, set_null=False)

	@rpc_method
	def licenseOnClient_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClients: List[dict] | List[LicenseOnClient] | dict | LicenseOnClient
	) -> None:
		ace = self._get_ace("licenseOnClient_createObjects")
		for licenseOnClient in forceList(licenseOnClients):
			self._mysql.insert_object(table="LICENSE_ON_CLIENT", obj=licenseOnClient, ace=ace, create=True, set_null=True)

	@rpc_method
	def licenseOnClient_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClients: List[dict] | List[LicenseOnClient] | dict | LicenseOnClient
	) -> None:
		ace = self._get_ace("licenseOnClient_updateObjects")
		for licenseOnClient in forceList(licenseOnClients):
			self._mysql.insert_object(table="LICENSE_ON_CLIENT", obj=licenseOnClient, ace=ace, create=True, set_null=False)

	@rpc_method
	def licenseOnClient_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[LicenseOnClient]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("licenseOnClient_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_ON_CLIENT", ace=ace, object_type=LicenseOnClient, attributes=attributes, filter=filter
		)

	@rpc_method
	def licenseOnClient_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("licenseOnClient_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_ON_CLIENT", object_type=LicenseOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def licenseOnClient_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("licenseOnClient_getObjects")
		return self._mysql.get_idents(table="LICENSE_ON_CLIENT", object_type=LicenseOnClient, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def licenseOnClient_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClients: List[dict] | List[LicenseOnClient] | dict | LicenseOnClient
	) -> None:
		ace = self._get_ace("licenseOnClient_deleteObjects")
		self._mysql.delete_objects(table="LICENSE_ON_CLIENT", object_type=LicenseOnClient, obj=licenseOnClients, ace=ace)

	@rpc_method
	def licenseOnClient_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.licenseOnClient_deleteObjects([{"id": id}])
