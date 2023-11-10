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

from opsicommon.objects import AuditSoftwareOnClient  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCAuditSoftwareOnClientMixin(Protocol):
	def auditSoftwareOnClient_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: list[dict] | list[AuditSoftwareOnClient]
	) -> None:
		self._mysql.bulk_insert_objects(table="SOFTWARE_CONFIG", objs=auditSoftwareOnClients)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClient: dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_insertObject")
		self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClient: dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_updateObject")
		self._mysql.insert_object(table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: list[dict] | list[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_createObjects")
		with self._mysql.session() as session:
			for auditSoftwareOnClient in forceList(auditSoftwareOnClients):
				self._mysql.insert_object(
					table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: list[dict] | list[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_updateObjects")
		with self._mysql.session() as session:
			for auditSoftwareOnClient in forceList(auditSoftwareOnClients):
				self._mysql.insert_object(
					table="SOFTWARE_CONFIG", obj=auditSoftwareOnClient, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_getObjects(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[AuditSoftwareOnClient]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_CONFIG", ace=ace, object_type=AuditSoftwareOnClient, attributes=attributes, filter=filter
		)

	@rpc_method(deprecated=True, alternative_method="auditSoftwareOnClient_getObjects", check_acl=False)
	def auditSoftwareOnClient_getHashes(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[dict]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_CONFIG", object_type=AuditSoftwareOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_getIdents(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_idents(
			table="SOFTWARE_CONFIG", object_type=AuditSoftwareOnClient, ace=ace, ident_type=returnType, filter=filter
		)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditSoftwareOnClients: list[dict] | list[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		if not auditSoftwareOnClients:
			return
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
		name: list[str] | str,
		version: list[str] | str,
		subVersion: list[str] | str,
		language: list[str] | str,
		architecture: list[str] | str,
		clientId: list[str] | str,
	) -> None:
		if name is None:
			name = []
		if version is None:
			version = []
		if subVersion is None:
			subVersion = []
		if language is None:
			language = []
		if architecture is None:
			architecture = []
		if clientId is None:
			clientId = []

		idents = self.auditSoftwareOnClient_getIdents(
			returnType="dict",
			name=name,
			version=version,
			subVersion=subVersion,
			language=language,
			architecture=architecture,
			clientId=clientId,
		)
		if idents:
			self.auditSoftwareOnClient_deleteObjects(idents)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_setObsolete(self: BackendProtocol, clientId: list[str] | str) -> None:  # pylint: disable=invalid-name
		idents = self.auditSoftwareOnClient_getIdents(returnType="dict", clientId=clientId)
		if idents:
			self.auditSoftwareOnClient_deleteObjects(idents)
