# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.license_contract
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import LicenseContract  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCLicenseContractMixin(Protocol):
	def licenseContract_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContracts: list[dict] | list[LicenseContract]
	) -> None:
		self._mysql.bulk_insert_objects(table="LICENSE_CONTRACT", objs=licenseContracts)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def licenseContract_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContract: dict | LicenseContract
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("licenseContract_insertObject")
		self._mysql.insert_object(table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def licenseContract_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContract: dict | LicenseContract
	) -> None:
		ace = self._get_ace("licenseContract_updateObject")
		self._mysql.insert_object(table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def licenseContract_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContracts: list[dict] | list[LicenseContract] | dict | LicenseContract
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("licenseContract_createObjects")
		with self._mysql.session() as session:
			for licenseContract in forceList(licenseContracts):
				self._mysql.insert_object(
					table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False)
	def licenseContract_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContracts: list[dict] | list[LicenseContract] | dict | LicenseContract
	) -> None:
		ace = self._get_ace("licenseContract_updateObjects")
		with self._mysql.session() as session:
			for licenseContract in forceList(licenseContracts):
				self._mysql.insert_object(
					table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def licenseContract_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[LicenseContract]:
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_objects(table="LICENSE_CONTRACT", ace=ace, object_type=LicenseContract, attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def licenseContract_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_CONTRACT", object_type=LicenseContract, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def licenseContract_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_idents(table="LICENSE_CONTRACT", object_type=LicenseContract, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def licenseContract_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseContracts: list[dict] | list[LicenseContract] | dict | LicenseContract
	) -> None:
		ace = self._get_ace("licenseContract_deleteObjects")
		self._mysql.delete_objects(table="LICENSE_CONTRACT", object_type=LicenseContract, obj=licenseContracts, ace=ace)

	@rpc_method(check_acl=False)
	def licenseContract_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.licenseContract_deleteObjects(self.licenseContract_getIdents(returnType="dict", id=id))

	@rpc_method(check_acl=False)
	def licenseContract_create(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		description: str | None = None,  # pylint: disable=unused-argument
		notes: str | None = None,  # pylint: disable=unused-argument
		partner: str | None = None,  # pylint: disable=unused-argument
		conclusionDate: str | None = None,  # pylint: disable=unused-argument
		notificationDate: str | None = None,  # pylint: disable=unused-argument
		expirationDate: str | None = None,  # pylint: disable=redefined-builtin,unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.licenseContract_createObjects(LicenseContract.fromHash(_hash))
