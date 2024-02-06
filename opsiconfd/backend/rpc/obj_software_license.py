# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.software_license
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import (
	ConcurrentSoftwareLicense,
	OEMSoftwareLicense,
	RetailSoftwareLicense,
	SoftwareLicense,
	VolumeSoftwareLicense,
)
from opsicommon.types import forceList

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCSoftwareLicenseMixin(Protocol):
	def softwareLicense_bulkInsertObjects(
		self: BackendProtocol,
		softwareLicenses: list[dict] | list[SoftwareLicense],
	) -> None:
		self._mysql.bulk_insert_objects(table="SOFTWARE_LICENSE", objs=softwareLicenses)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def softwareLicense_insertObject(
		self: BackendProtocol,
		softwareLicense: dict | SoftwareLicense,
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("softwareLicense_insertObject")
		self._mysql.insert_object(table="SOFTWARE_LICENSE", obj=softwareLicense, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def softwareLicense_updateObject(
		self: BackendProtocol,
		softwareLicense: dict | SoftwareLicense,
	) -> None:
		ace = self._get_ace("softwareLicense_updateObject")
		self._mysql.insert_object(table="SOFTWARE_LICENSE", obj=softwareLicense, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def softwareLicense_createObjects(
		self: BackendProtocol,
		softwareLicenses: list[dict] | list[SoftwareLicense] | dict | SoftwareLicense,
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("softwareLicense_createObjects")
		with self._mysql.session() as session:
			for softwareLicense in forceList(softwareLicenses):
				self._mysql.insert_object(
					table="SOFTWARE_LICENSE", obj=softwareLicense, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False)
	def softwareLicense_updateObjects(
		self: BackendProtocol,
		softwareLicenses: list[dict] | list[SoftwareLicense] | dict | SoftwareLicense,
	) -> None:
		ace = self._get_ace("softwareLicense_updateObjects")
		with self._mysql.session() as session:
			for softwareLicense in forceList(softwareLicenses):
				self._mysql.insert_object(
					table="SOFTWARE_LICENSE", obj=softwareLicense, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def softwareLicense_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[SoftwareLicense]:
		ace = self._get_ace("softwareLicense_getObjects")
		return self._mysql.get_objects(table="SOFTWARE_LICENSE", ace=ace, object_type=SoftwareLicense, attributes=attributes, filter=filter)

	@rpc_method(deprecated=True, alternative_method="softwareLicense_getObjects", check_acl=False)
	def softwareLicense_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("softwareLicense_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_LICENSE", object_type=SoftwareLicense, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def softwareLicense_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("softwareLicense_getObjects")
		return self._mysql.get_idents(table="SOFTWARE_LICENSE", object_type=SoftwareLicense, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def softwareLicense_deleteObjects(
		self: BackendProtocol, softwareLicenses: list[dict] | list[SoftwareLicense] | dict | SoftwareLicense
	) -> None:
		if not softwareLicenses:
			return
		ace = self._get_ace("softwareLicense_deleteObjects")
		self._mysql.delete_objects(table="SOFTWARE_LICENSE", object_type=SoftwareLicense, obj=softwareLicenses, ace=ace)

	@rpc_method(check_acl=False)
	def softwareLicense_delete(self: BackendProtocol, id: list[str] | str) -> None:
		idents = self.softwareLicense_getIdents(returnType="dict", id=id)
		if idents:
			self.softwareLicense_deleteObjects(idents)

	@rpc_method(check_acl=False)
	def softwareLicense_createRetail(
		self: BackendProtocol,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicense_createObjects(RetailSoftwareLicense.fromHash(_hash))

	@rpc_method(check_acl=False)
	def softwareLicense_createOEM(
		self: BackendProtocol,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicense_createObjects(OEMSoftwareLicense.fromHash(_hash))

	@rpc_method(check_acl=False)
	def softwareLicense_createVolume(
		self: BackendProtocol,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicense_createObjects(VolumeSoftwareLicense.fromHash(_hash))

	@rpc_method(check_acl=False)
	def softwareLicense_createConcurrent(
		self: BackendProtocol,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicense_createObjects(ConcurrentSoftwareLicense.fromHash(_hash))
