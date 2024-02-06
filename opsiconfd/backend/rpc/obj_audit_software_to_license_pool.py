# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.audit_software_to_license_pool
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import AuditSoftwareToLicensePool
from opsicommon.types import forceList

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCAuditSoftwareToLicensePoolMixin(Protocol):
	def auditSoftwareToLicensePool_bulkInsertObjects(
		self: BackendProtocol, auditSoftwareToLicensePools: list[dict] | list[AuditSoftwareToLicensePool]
	) -> None:
		self._mysql.bulk_insert_objects(table="AUDIT_SOFTWARE_TO_LICENSE_POOL", objs=auditSoftwareToLicensePools)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_insertObject(
		self: BackendProtocol,
		auditSoftwareToLicensePool: dict | AuditSoftwareToLicensePool,
	) -> None:
		ace = self._get_ace("auditSoftwareToLicensePool_insertObject")
		self._mysql.insert_object(
			table="AUDIT_SOFTWARE_TO_LICENSE_POOL", obj=auditSoftwareToLicensePool, ace=ace, create=True, set_null=True
		)

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_updateObject(
		self: BackendProtocol, auditSoftwareToLicensePool: dict | AuditSoftwareToLicensePool
	) -> None:
		ace = self._get_ace("auditSoftwareToLicensePool_updateObject")
		self._mysql.insert_object(
			table="AUDIT_SOFTWARE_TO_LICENSE_POOL", obj=auditSoftwareToLicensePool, ace=ace, create=False, set_null=False
		)

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_createObjects(
		self: BackendProtocol,
		auditSoftwareToLicensePools: list[dict] | list[AuditSoftwareToLicensePool] | dict | AuditSoftwareToLicensePool,
	) -> None:
		ace = self._get_ace("auditSoftwareToLicensePool_createObjects")
		with self._mysql.session() as session:
			for auditSoftwareToLicensePool in forceList(auditSoftwareToLicensePools):
				self._mysql.insert_object(
					table="AUDIT_SOFTWARE_TO_LICENSE_POOL",
					obj=auditSoftwareToLicensePool,
					ace=ace,
					create=True,
					set_null=True,
					session=session,
				)

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_updateObjects(
		self: BackendProtocol,
		auditSoftwareToLicensePools: list[dict] | list[AuditSoftwareToLicensePool] | dict | AuditSoftwareToLicensePool,
	) -> None:
		ace = self._get_ace("auditSoftwareToLicensePool_updateObjects")
		with self._mysql.session() as session:
			for auditSoftwareToLicensePool in forceList(auditSoftwareToLicensePools):
				self._mysql.insert_object(
					table="AUDIT_SOFTWARE_TO_LICENSE_POOL",
					obj=auditSoftwareToLicensePool,
					ace=ace,
					create=True,
					set_null=False,
					session=session,
				)

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[AuditSoftwareToLicensePool]:
		ace = self._get_ace("auditSoftwareToLicensePool_getObjects")
		return self._mysql.get_objects(
			table="AUDIT_SOFTWARE_TO_LICENSE_POOL", ace=ace, object_type=AuditSoftwareToLicensePool, attributes=attributes, filter=filter
		)

	@rpc_method(deprecated=True, alternative_method="auditSoftwareToLicensePool_getObjects", check_acl=False)
	def auditSoftwareToLicensePool_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("auditSoftwareToLicensePool_getObjects")
		return self._mysql.get_objects(
			table="AUDIT_SOFTWARE_TO_LICENSE_POOL",
			object_type=AuditSoftwareToLicensePool,
			ace=ace,
			return_type="dict",
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("auditSoftwareToLicensePool_getObjects")
		return self._mysql.get_idents(
			table="AUDIT_SOFTWARE_TO_LICENSE_POOL", object_type=AuditSoftwareToLicensePool, ace=ace, ident_type=returnType, filter=filter
		)

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_deleteObjects(
		self: BackendProtocol,
		auditSoftwareToLicensePools: list[dict] | list[AuditSoftwareToLicensePool] | dict | AuditSoftwareToLicensePool,
	) -> None:
		if not auditSoftwareToLicensePools:
			return
		ace = self._get_ace("auditSoftwareToLicensePool_deleteObjects")
		self._mysql.delete_objects(
			table="AUDIT_SOFTWARE_TO_LICENSE_POOL", object_type=AuditSoftwareToLicensePool, obj=auditSoftwareToLicensePools, ace=ace
		)

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_create(
		self: BackendProtocol, name: str, version: str, subVersion: str, language: str, architecture: str, licensePoolId: str
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.auditSoftwareToLicensePool_createObjects(AuditSoftwareToLicensePool.fromHash(_hash))

	@rpc_method(check_acl=False)
	def auditSoftwareToLicensePool_delete(
		self: BackendProtocol, name: str, version: str, subVersion: str, language: str, architecture: str, licensePoolId: str
	) -> None:
		idents = self.auditSoftwareToLicensePool_getIdents(
			returnType="dict",
			name=name,
			version=version,
			subVersion=subVersion,
			language=language,
			architecture=architecture,
			licensePoolId=licensePoolId,
		)
		if idents:
			self.auditSoftwareToLicensePool_deleteObjects(idents)
