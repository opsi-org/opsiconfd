# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.license_pool
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import LicensePool  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCLicensePoolMixin(Protocol):
	@rpc_method
	def licensePool_insertObject(self: BackendProtocol, licensePool: dict | LicensePool) -> None:  # pylint: disable=invalid-name
		self._check_module("license_management")
		ace = self._get_ace("licensePool_insertObject")
		self._mysql.insert_object(table="LICENSE_POOL", obj=licensePool, ace=ace, create=True, set_null=True)

	@rpc_method
	def licensePool_updateObject(self: BackendProtocol, licensePool: dict | LicensePool) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("licensePool_updateObject")
		self._mysql.insert_object(table="LICENSE_POOL", obj=licensePool, ace=ace, create=False, set_null=False)

	@rpc_method
	def licensePool_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licensePools: List[dict] | List[LicensePool] | dict | LicensePool
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("licensePool_createObjects")
		for licensePool in forceList(licensePools):
			self._mysql.insert_object(table="LICENSE_POOL", obj=licensePool, ace=ace, create=True, set_null=True)

	@rpc_method
	def licensePool_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licensePools: List[dict] | List[LicensePool] | dict | LicensePool
	) -> None:
		ace = self._get_ace("licensePool_updateObjects")
		for licensePool in forceList(licensePools):
			self._mysql.insert_object(table="LICENSE_POOL", obj=licensePool, ace=ace, create=True, set_null=False)

	@rpc_method
	def licensePool_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[LicensePool]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("licensePool_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_POOL", ace=ace, object_type=LicensePool, attributes=attributes, filter=filter
		)

	@rpc_method
	def licensePool_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("licensePool_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_POOL", object_type=LicensePool, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def licensePool_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("licensePool_getObjects")
		return self._mysql.get_idents(table="LICENSE_POOL", object_type=LicensePool, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def licensePool_deleteObjects(self: BackendProtocol, licensePools: List[dict] | List[LicensePool] | dict | LicensePool) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("licensePool_deleteObjects")
		self._mysql.delete_objects(table="LICENSE_POOL", object_type=LicensePool, obj=licensePools, ace=ace)

	@rpc_method
	def licensePool_create(self: BackendProtocol, id: str, description: str = None, productIds: list[str] = None) -> None:  # pylint: disable=redefined-builtin,unused-argument,invalid-name
		_hash = locals()
		del _hash["self"]
		self.licensePool_createObjects(LicensePool.fromHash(_hash))

	@rpc_method
	def licensePool_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.licensePool_deleteObjects([{"id": id}])
