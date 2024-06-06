# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.software_license_to_license_pool
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import SoftwareLicenseToLicensePool
from opsicommon.types import forceList

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCSoftwareLicenseToLicensePoolMixin(Protocol):
	def softwareLicenseToLicensePool_bulkInsertObjects(
		self: BackendProtocol, softwareLicenseToLicensePools: list[SoftwareLicenseToLicensePool | dict[str, Any]]
	) -> None:
		self._mysql.bulk_insert_objects(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL",
			objs=softwareLicenseToLicensePools,  # type: ignore[arg-type]
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_insertObject(
		self: BackendProtocol,
		softwareLicenseToLicensePool: dict | SoftwareLicenseToLicensePool,
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_insertObject")
		self._mysql.insert_object(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", obj=softwareLicenseToLicensePool, ace=ace, create=True, set_null=True
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_updateObject(
		self: BackendProtocol, softwareLicenseToLicensePool: dict | SoftwareLicenseToLicensePool
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_updateObject")
		self._mysql.insert_object(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", obj=softwareLicenseToLicensePool, ace=ace, create=False, set_null=False
		)

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_createObjects(
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
	def softwareLicenseToLicensePool_updateObjects(
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
	def softwareLicenseToLicensePool_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[SoftwareLicenseToLicensePool]:
		ace = self._get_ace("softwareLicenseToLicensePool_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL",
			ace=ace,
			object_type=SoftwareLicenseToLicensePool,
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(deprecated=True, alternative_method="softwareLicenseToLicensePool_getObjects", check_acl=False)
	def softwareLicenseToLicensePool_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
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
	def softwareLicenseToLicensePool_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
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
	def softwareLicenseToLicensePool_deleteObjects(
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
	def softwareLicenseToLicensePool_create(
		self: BackendProtocol, softwareLicenseId: str, licensePoolId: str, licenseKey: str | None = None
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.softwareLicenseToLicensePool_createObjects(SoftwareLicenseToLicensePool.fromHash(_hash))

	@rpc_method(check_acl=False)
	def softwareLicenseToLicensePool_delete(
		self: BackendProtocol, softwareLicenseId: list[str] | str, licensePoolId: list[str] | str
	) -> None:
		idents = self.softwareLicenseToLicensePool_getIdents(
			returnType="dict", softwareLicenseId=softwareLicenseId, licensePoolId=licensePoolId
		)
		if idents:
			self.softwareLicenseToLicensePool_deleteObjects(idents)
