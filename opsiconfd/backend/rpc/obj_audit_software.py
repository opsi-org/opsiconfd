# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.audit_hardware
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import AuditSoftware  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCAuditSoftwareMixin(Protocol):
	def auditSoftware_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwares: list[dict] | list[AuditSoftware]
	) -> None:
		self._mysql.bulk_insert_objects(table="SOFTWARE", objs=auditSoftwares)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def auditSoftware_insertObject(self: BackendProtocol, auditSoftware: dict | AuditSoftware) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditSoftware_insertObject")
		self._mysql.insert_object(table="SOFTWARE", obj=auditSoftware, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditSoftware_updateObject(self: BackendProtocol, auditSoftware: dict | AuditSoftware) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditSoftware_updateObject")
		self._mysql.insert_object(table="SOFTWARE", obj=auditSoftware, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def auditSoftware_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwares: list[dict] | list[AuditSoftware] | dict | AuditSoftware
	) -> None:
		ace = self._get_ace("auditSoftware_createObjects")
		with self._mysql.session() as session:
			for auditSoftware in forceList(auditSoftwares):
				self._mysql.insert_object(table="SOFTWARE", obj=auditSoftware, ace=ace, create=True, set_null=True, session=session)

	@rpc_method(check_acl=False)
	def auditSoftware_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwares: list[dict] | list[AuditSoftware] | dict | AuditSoftware
	) -> None:
		ace = self._get_ace("auditSoftware_updateObjects")
		with self._mysql.session() as session:
			for auditSoftware in forceList(auditSoftwares):
				self._mysql.insert_object(table="SOFTWARE", obj=auditSoftware, ace=ace, create=True, set_null=False, session=session)

	@rpc_method(check_acl=False)
	def auditSoftware_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[AuditSoftware]:
		ace = self._get_ace("auditSoftware_getObjects")
		return self._mysql.get_objects(table="SOFTWARE", ace=ace, object_type=AuditSoftware, attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def auditSoftware_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ace = self._get_ace("auditSoftware_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE", object_type=AuditSoftware, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def auditSoftware_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("auditSoftware_getObjects")
		return self._mysql.get_idents(table="SOFTWARE", object_type=AuditSoftware, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def auditSoftware_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwares: list[dict] | list[AuditSoftware] | dict | AuditSoftware
	) -> None:
		ace = self._get_ace("auditSoftware_deleteObjects")
		self._mysql.delete_objects(table="SOFTWARE", object_type=AuditSoftware, obj=auditSoftwares, ace=ace)

	@rpc_method(check_acl=False)
	def auditSoftware_create(  # pylint: disable=invalid-name,unused-argument,too-many-arguments
		self: BackendProtocol,
		name: str,
		version: str,
		subVersion: str,
		language: str,
		architecture: str,
		windowsSoftwareId: str | None = None,
		windowsDisplayName: str | None = None,
		windowsDisplayVersion: str | None = None,
		installSize: int | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.auditSoftware_createObjects(AuditSoftware.fromHash(_hash))

	@rpc_method(check_acl=False)
	def auditSoftware_delete(  # pylint: disable=redefined-builtin,invalid-name,too-many-arguments
		self: BackendProtocol, name: str, version: str, subVersion: str, language: str, architecture: str
	) -> None:
		idents = self.auditSoftware_getIdents(
			returnType="dict", name=name, version=version, subVersion=subVersion, language=language, architecture=architecture
		)
		if idents:
			self.auditSoftware_deleteObjects(idents)
