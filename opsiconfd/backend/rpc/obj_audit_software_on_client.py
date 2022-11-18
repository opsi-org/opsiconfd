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

from opsicommon.objects import AuditSoftwareOnClient  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCAuditSoftwareOnClientMixin(Protocol):
	@rpc_method
	def auditSoftwareOnClient_insertObject(self: BackendProtocol, auditSoftwareOnClient: dict | AuditSoftwareOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditSoftwareOnClient_insertObject")
		self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=True)

	@rpc_method
	def auditSoftwareOnClient_updateObject(self: BackendProtocol, auditSoftwareOnClient: dict | AuditSoftwareOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditSoftwareOnClient_updateObject")
		self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=False, set_null=False)

	@rpc_method
	def auditSoftwareOnClient_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: List[dict] | List[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_createObjects")
		for auditSoftwareOnClient in forceList(auditSoftwareOnClients):
			self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=True)

	@rpc_method
	def auditSoftwareOnClient_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: List[dict] | List[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_updateObjects")
		for auditSoftwareOnClient in forceList(auditSoftwareOnClients):
			self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=False)

	@rpc_method
	def auditSoftwareOnClient_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[AuditSoftwareOnClient]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_CONFIG", ace=ace, object_type=AuditSoftwareOnClient, attributes=attributes, filter=filter
		)

	@rpc_method
	def auditSoftwareOnClient_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_CONFIG", object_type=AuditSoftwareOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def auditSoftwareOnClient_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_idents(table="SOFTWARE_CONFIG", object_type=AuditSoftwareOnClient, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def auditSoftwareOnClient_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: List[dict] | List[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_deleteObjects")
		self._mysql.delete_objects(table="SOFTWARE_CONFIG", object_type=AuditSoftwareOnClient, obj=auditSoftwareOnClients, ace=ace)

	@rpc_method
	def auditSoftwareOnClient_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.auditSoftwareOnClient_deleteObjects([{"id": id}])
