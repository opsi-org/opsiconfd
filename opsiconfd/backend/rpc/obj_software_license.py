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

from opsicommon.objects import (  # type: ignore[import]
	ConcurrentSoftwareLicense,
	OEMSoftwareLicense,
	RetailSoftwareLicense,
	SoftwareLicense,
	VolumeSoftwareLicense,
)
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCSoftwareLicenseMixin(Protocol):
	def softwareLicense_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenses: list[dict] | list[SoftwareLicense],  # pylint: disable=invalid-name
	) -> None:
		self._mysql.bulk_insert_objects(table="SOFTWARE_LICENSE", objs=softwareLicenses)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def softwareLicense_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicense: dict | SoftwareLicense,  # pylint: disable=invalid-name
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("softwareLicense_insertObject")
		self._mysql.insert_object(table="SOFTWARE_LICENSE", obj=softwareLicense, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def softwareLicense_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicense: dict | SoftwareLicense,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("softwareLicense_updateObject")
		self._mysql.insert_object(table="SOFTWARE_LICENSE", obj=softwareLicense, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def softwareLicense_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenses: list[dict] | list[SoftwareLicense] | dict | SoftwareLicense,  # pylint: disable=invalid-name
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("softwareLicense_createObjects")
		with self._mysql.session() as session:
			for softwareLicense in forceList(softwareLicenses):
				self._mysql.insert_object(
					table="SOFTWARE_LICENSE", obj=softwareLicense, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False)
	def softwareLicense_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenses: list[dict] | list[SoftwareLicense] | dict | SoftwareLicense,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("softwareLicense_updateObjects")
		with self._mysql.session() as session:
			for softwareLicense in forceList(softwareLicenses):
				self._mysql.insert_object(
					table="SOFTWARE_LICENSE", obj=softwareLicense, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def softwareLicense_getObjects(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[SoftwareLicense]:
		ace = self._get_ace("softwareLicense_getObjects")
		return self._mysql.get_objects(table="SOFTWARE_LICENSE", ace=ace, object_type=SoftwareLicense, attributes=attributes, filter=filter)

	@rpc_method(deprecated=True, alternative_method="softwareLicense_getObjects", check_acl=False)
	def softwareLicense_getHashes(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("softwareLicense_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_LICENSE", object_type=SoftwareLicense, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def softwareLicense_getIdents(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("softwareLicense_getObjects")
		return self._mysql.get_idents(table="SOFTWARE_LICENSE", object_type=SoftwareLicense, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def softwareLicense_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenses: list[dict] | list[SoftwareLicense] | dict | SoftwareLicense
	) -> None:
		if not softwareLicenses:
			return
		ace = self._get_ace("softwareLicense_deleteObjects")
		self._mysql.delete_objects(table="SOFTWARE_LICENSE", object_type=SoftwareLicense, obj=softwareLicenses, ace=ace)

	@rpc_method(check_acl=False)
	def softwareLicense_delete(self: BackendProtocol, id: list[str] | str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		idents = self.softwareLicense_getIdents(returnType="dict", id=id)
		if idents:
			self.softwareLicense_deleteObjects(idents)

	@rpc_method(check_acl=False)
	def softwareLicense_createRetail(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		licenseContractId: str,  # pylint: disable=unused-argument
		maxInstallations: int | None = None,  # pylint: disable=unused-argument
		boundToHost: str | None = None,  # pylint: disable=unused-argument
		expirationDate: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicense_createObjects(RetailSoftwareLicense.fromHash(_hash))

	@rpc_method(check_acl=False)
	def softwareLicense_createOEM(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		licenseContractId: str,  # pylint: disable=unused-argument
		maxInstallations: int | None = None,  # pylint: disable=unused-argument
		boundToHost: str | None = None,  # pylint: disable=unused-argument
		expirationDate: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicense_createObjects(OEMSoftwareLicense.fromHash(_hash))

	@rpc_method(check_acl=False)
	def softwareLicense_createVolume(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		licenseContractId: str,  # pylint: disable=unused-argument
		maxInstallations: int | None = None,  # pylint: disable=unused-argument
		boundToHost: str | None = None,  # pylint: disable=unused-argument
		expirationDate: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicense_createObjects(VolumeSoftwareLicense.fromHash(_hash))

	@rpc_method(check_acl=False)
	def softwareLicense_createConcurrent(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		licenseContractId: str,  # pylint: disable=unused-argument
		maxInstallations: int | None = None,  # pylint: disable=unused-argument
		boundToHost: str | None = None,  # pylint: disable=unused-argument
		expirationDate: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicense_createObjects(ConcurrentSoftwareLicense.fromHash(_hash))
