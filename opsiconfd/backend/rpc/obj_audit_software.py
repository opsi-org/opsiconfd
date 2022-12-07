# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.audit_hardware
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import AuditSoftware  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCAuditSoftwareMixin(Protocol):
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
		self: BackendProtocol, auditSoftwares: List[dict] | List[AuditSoftware] | dict | AuditSoftware
	) -> None:
		ace = self._get_ace("auditSoftware_createObjects")
		for auditSoftware in forceList(auditSoftwares):
			self._mysql.insert_object(table="SOFTWARE", obj=auditSoftware, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditSoftware_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwares: List[dict] | List[AuditSoftware] | dict | AuditSoftware
	) -> None:
		ace = self._get_ace("auditSoftware_updateObjects")
		for auditSoftware in forceList(auditSoftwares):
			self._mysql.insert_object(table="SOFTWARE", obj=auditSoftware, ace=ace, create=True, set_null=False)

	@rpc_method(check_acl=False)
	def auditSoftware_getObjects(self: BackendProtocol, attributes: List[str] | None = None, **filter: Any) -> List[AuditSoftware]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("auditSoftware_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE", ace=ace, object_type=AuditSoftware, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def auditSoftware_getHashes(self: BackendProtocol, attributes: List[str] | None = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("auditSoftware_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE", object_type=AuditSoftware, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def auditSoftware_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("auditSoftware_getObjects")
		return self._mysql.get_idents(table="SOFTWARE", object_type=AuditSoftware, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def auditSoftware_deleteObjects(self: BackendProtocol, auditSoftwares: List[dict] | List[AuditSoftware] | dict | AuditSoftware) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditSoftware_deleteObjects")
		self._mysql.delete_objects(table="SOFTWARE", object_type=AuditSoftware, obj=auditSoftwares, ace=ace)

	@rpc_method(check_acl=False)
	def auditSoftware_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.auditSoftware_deleteObjects([{"id": id}])
