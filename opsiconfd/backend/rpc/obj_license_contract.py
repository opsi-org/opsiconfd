# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.license_contract
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import LicenseContract  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCLicenseContractMixin(Protocol):
	@rpc_method
	def licenseContract_insertObject(self: BackendProtocol, licenseContract: dict | LicenseContract) -> None:  # pylint: disable=invalid-name
		self._check_module("license_management")
		ace = self._get_ace("licenseContract_insertObject")
		self._mysql.insert_object(table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=True, set_null=True)

	@rpc_method
	def licenseContract_updateObject(self: BackendProtocol, licenseContract: dict | LicenseContract) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("licenseContract_updateObject")
		self._mysql.insert_object(table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=False, set_null=False)

	@rpc_method
	def licenseContract_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContracts: List[dict] | List[LicenseContract] | dict | LicenseContract
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("licenseContract_createObjects")
		for licenseContract in forceList(licenseContracts):
			self._mysql.insert_object(table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=True, set_null=True)

	@rpc_method
	def licenseContract_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContracts: List[dict] | List[LicenseContract] | dict | LicenseContract
	) -> None:
		ace = self._get_ace("licenseContract_updateObjects")
		for licenseContract in forceList(licenseContracts):
			self._mysql.insert_object(table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=True, set_null=False)

	@rpc_method
	def licenseContract_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[LicenseContract]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_CONTRACT", ace=ace, object_type=LicenseContract, attributes=attributes, filter=filter
		)

	@rpc_method
	def licenseContract_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_CONTRACT", object_type=LicenseContract, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def licenseContract_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_idents(table="LICENSE_CONTRACT", object_type=LicenseContract, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def licenseContract_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContracts: List[dict] | List[LicenseContract] | dict | LicenseContract
	) -> None:
		ace = self._get_ace("licenseContract_deleteObjects")
		self._mysql.delete_objects(table="LICENSE_CONTRACT", object_type=LicenseContract, obj=licenseContracts, ace=ace)

	@rpc_method
	def licenseContract_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.licenseContract_deleteObjects([{"id": id}])

	@rpc_method
	def licenseContract_create(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		description: str = None,  # pylint: disable=unused-argument
		notes: str = None,  # pylint: disable=unused-argument
		partner: str = None,  # pylint: disable=unused-argument
		conclusionDate: str = None,  # pylint: disable=unused-argument
		notificationDate: str = None,  # pylint: disable=unused-argument
		expirationDate: str = None,  # pylint: disable=redefined-builtin,unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.licenseContract_createObjects(LicenseContract.fromHash(_hash))
