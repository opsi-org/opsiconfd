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
	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_insertObject(self: BackendProtocol, auditSoftwareOnClient: dict | AuditSoftwareOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditSoftwareOnClient_insertObject")
		self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_updateObject(self: BackendProtocol, auditSoftwareOnClient: dict | AuditSoftwareOnClient) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditSoftwareOnClient_updateObject")
		self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: List[dict] | List[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_createObjects")
		with self._mysql.session() as session:
			for auditSoftwareOnClient in forceList(auditSoftwareOnClients):
				self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=True, session=session)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: List[dict] | List[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_updateObjects")
		with self._mysql.session() as session:
			for auditSoftwareOnClient in forceList(auditSoftwareOnClients):
				self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=False, session=session)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: List[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> List[AuditSoftwareOnClient]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_CONFIG", ace=ace, object_type=AuditSoftwareOnClient, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_getHashes(self: BackendProtocol, attributes: List[str] | None = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_CONFIG", object_type=AuditSoftwareOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_idents(table="SOFTWARE_CONFIG", object_type=AuditSoftwareOnClient, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: List[dict] | List[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_deleteObjects")
		self._mysql.delete_objects(table="SOFTWARE_CONFIG", object_type=AuditSoftwareOnClient, obj=auditSoftwareOnClients, ace=ace)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_create(  # pylint: disable=invalid-name,too-many-arguments,too-many-locals
		self: BackendProtocol,
		name: str,  # pylint: disable=unused-argument
		version: str,  # pylint: disable=unused-argument
		subVersion: str,  # pylint: disable=invalid-name,unused-argument
		language: str,  # pylint: disable=unused-argument
		architecture: str,  # pylint: disable=unused-argument
		clientId: str,  # pylint: disable=invalid-name,unused-argument
		uninstallString: str | None = None,  # pylint: disable=invalid-name,unused-argument
		binaryName: str | None = None,  # pylint: disable=invalid-name,unused-argument
		firstseen: str | None = None,  # pylint: disable=unused-argument
		lastseen: str | None = None,  # pylint: disable=unused-argument
		state: int | None = None,  # pylint: disable=unused-argument
		usageFrequency: int | None = None,  # pylint: disable=invalid-name,unused-argument
		lastUsed: str | None = None,  # pylint: disable=invalid-name,unused-argument
		licenseKey: str | None = None,  # pylint: disable=invalid-name,unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		return self.auditSoftwareOnClient_createObjects(AuditSoftwareOnClient.fromHash(_hash))

	def auditSoftwareOnClient_delete(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		name: list[str] | str | None = None,
		version: list[str] | str | None = None,
		subVersion: list[str] | str | None = None,
		language: list[str] | str | None = None,
		architecture: list[str] | str | None = None,
		clientId: list[str] | str | None = None
	) -> None:
		if name is None:
			name = []  # pylint: disable=use-tuple-over-list
		if version is None:
			version = []  # pylint: disable=use-tuple-over-list
		if subVersion is None:
			subVersion = []  # pylint: disable=use-tuple-over-list
		if language is None:
			language = []  # pylint: disable=use-tuple-over-list
		if architecture is None:
			architecture = []  # pylint: disable=use-tuple-over-list
		if clientId is None:
			clientId = []  # pylint: disable=use-tuple-over-list

		self.auditSoftwareOnClient_deleteObjects(
			self.auditSoftwareOnClient_getIdents(
				returnType="dict", name=name, version=version, subVersion=subVersion, language=language, architecture=architecture, clientId=clientId
			)
		)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_setObsolete(self: BackendProtocol, clientId: List[str] | str) -> None:  # pylint: disable=invalid-name
		self.auditSoftwareOnClient_deleteObjects(
			self.auditSoftwareOnClient_getIdents(
				returnType="dict", clientId=clientId
			)
		)
