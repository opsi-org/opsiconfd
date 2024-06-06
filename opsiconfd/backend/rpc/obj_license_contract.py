# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.license_contract
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import LicenseContract
from opsicommon.types import forceList

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCLicenseContractMixin(Protocol):
	def licenseContract_bulkInsertObjects(self: BackendProtocol, licenseContracts: list[dict] | list[LicenseContract]) -> None:
		self._mysql.bulk_insert_objects(table="LICENSE_CONTRACT", objs=licenseContracts)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def licenseContract_insertObject(self: BackendProtocol, licenseContract: dict | LicenseContract) -> None:
		self._check_module("license_management")
		ace = self._get_ace("licenseContract_insertObject")
		self._mysql.insert_object(table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def licenseContract_updateObject(self: BackendProtocol, licenseContract: dict | LicenseContract) -> None:
		ace = self._get_ace("licenseContract_updateObject")
		self._mysql.insert_object(table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def licenseContract_createObjects(
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
	def licenseContract_updateObjects(
		self: BackendProtocol, licenseContracts: list[dict] | list[LicenseContract] | dict | LicenseContract
	) -> None:
		ace = self._get_ace("licenseContract_updateObjects")
		with self._mysql.session() as session:
			for licenseContract in forceList(licenseContracts):
				self._mysql.insert_object(
					table="LICENSE_CONTRACT", obj=licenseContract, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def licenseContract_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[LicenseContract]:
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_objects(table="LICENSE_CONTRACT", ace=ace, object_type=LicenseContract, attributes=attributes, filter=filter)

	@rpc_method(deprecated=True, alternative_method="licenseContract_getObjects", check_acl=False)
	def licenseContract_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_CONTRACT", object_type=LicenseContract, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def licenseContract_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("licenseContract_getObjects")
		return self._mysql.get_idents(table="LICENSE_CONTRACT", object_type=LicenseContract, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def licenseContract_deleteObjects(
		self: BackendProtocol, licenseContracts: list[dict] | list[LicenseContract] | dict | LicenseContract
	) -> None:
		if not licenseContracts:
			return
		ace = self._get_ace("licenseContract_deleteObjects")
		self._mysql.delete_objects(table="LICENSE_CONTRACT", object_type=LicenseContract, obj=licenseContracts, ace=ace)

	@rpc_method(check_acl=False)
	def licenseContract_delete(self: BackendProtocol, id: list[str] | str) -> None:
		idents = self.licenseContract_getIdents(returnType="dict", id=id)
		if idents:
			self.licenseContract_deleteObjects(idents)

	@rpc_method(check_acl=False)
	def licenseContract_create(
		self: BackendProtocol,
		id: str,
		description: str | None = None,
		notes: str | None = None,
		partner: str | None = None,
		conclusionDate: str | None = None,
		notificationDate: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.licenseContract_createObjects(LicenseContract.fromHash(_hash))
