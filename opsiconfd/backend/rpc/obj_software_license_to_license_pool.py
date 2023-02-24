# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.software_license_to_license_pool
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import SoftwareLicenseToLicensePool  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCSoftwareLicenseToLicensePoolMixin(Protocol):
	def softwareLicenseToLicensePool_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseToLicensePools: list[dict] | list[SoftwareLicenseToLicensePool]
	) -> None:
		self._mysql.bulk_insert_objects(table="SOFTWARE_LICENSE_TO_LICENSE_POOL", objs=softwareLicenseToLicensePools)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseToLicensePool: dict | SoftwareLicenseToLicensePool  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_insertObject")
		self._mysql.insert_object(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", obj=softwareLicenseToLicensePool, ace=ace, create=True, set_null=True
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseToLicensePool: dict | SoftwareLicenseToLicensePool
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_updateObject")
		self._mysql.insert_object(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", obj=softwareLicenseToLicensePool, ace=ace, create=False, set_null=False
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenseToLicensePools: list[dict[str, Any]]
		| list[SoftwareLicenseToLicensePool]
		| dict[str, Any]
		| SoftwareLicenseToLicensePool,
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_createObjects")
		with self._mysql.session() as session:
			for softwareLicenseToLicensePool in forceList(softwareLicenseToLicensePools):
				self._mysql.insert_object(
					table="SOFTWARE_LICENSE_TO_LICENSE_POOL",
					obj=softwareLicenseToLicensePool,
					ace=ace,
					create=True,
					set_null=True,
					session=session,
				)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenseToLicensePools: list[dict[str, Any]]
		| list[SoftwareLicenseToLicensePool]
		| dict[str, Any]
		| SoftwareLicenseToLicensePool,
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_updateObjects")
		with self._mysql.session() as session:
			for softwareLicenseToLicensePool in forceList(softwareLicenseToLicensePools):
				self._mysql.insert_object(
					table="SOFTWARE_LICENSE_TO_LICENSE_POOL",
					obj=softwareLicenseToLicensePool,
					ace=ace,
					create=True,
					set_null=False,
					session=session,
				)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin,invalid-name
	) -> list[SoftwareLicenseToLicensePool]:
		ace = self._get_ace("softwareLicenseToLicensePool_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL",
			ace=ace,
			object_type=SoftwareLicenseToLicensePool,
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[dict[str, Any]]:
		ace = self._get_ace("softwareLicenseToLicensePool_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL",
			object_type=SoftwareLicenseToLicensePool,
			ace=ace,
			return_type="dict",
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict[str, Any]] | list[list] | list[tuple]:
		ace = self._get_ace("softwareLicenseToLicensePool_getObjects")
		return self._mysql.get_idents(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL",
			object_type=SoftwareLicenseToLicensePool,
			ace=ace,
			ident_type=returnType,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenseToLicensePools: list[dict[str, Any]]
		| list[SoftwareLicenseToLicensePool]
		| dict[str, Any]
		| SoftwareLicenseToLicensePool,
	) -> None:
		if not softwareLicenseToLicensePools:
			return
		ace = self._get_ace("softwareLicenseToLicensePool_deleteObjects")
		self._mysql.delete_objects(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", object_type=SoftwareLicenseToLicensePool, obj=softwareLicenseToLicensePools, ace=ace
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_create(  # pylint: disable=unused-argument,invalid-name
		self: BackendProtocol, softwareLicenseId: str, licensePoolId: str, licenseKey: str | None = None
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicenseToLicensePool_createObjects(SoftwareLicenseToLicensePool.fromHash(_hash))

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_delete(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, softwareLicenseId: list[str] | str, licensePoolId: list[str] | str
	) -> None:
		idents = self.softwareLicenseToLicensePool_getIdents(
			returnType="dict", softwareLicenseId=softwareLicenseId, licensePoolId=licensePoolId
		)
		if idents:
			self.softwareLicenseToLicensePool_deleteObjects(idents)
