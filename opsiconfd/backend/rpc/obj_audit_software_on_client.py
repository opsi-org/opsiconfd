# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.audit_hardware
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import BackendReferentialIntegrityError
from opsicommon.objects import AuditSoftwareOnClient
from opsicommon.types import forceList

from ..auth import RPCACE
from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCAuditSoftwareOnClientMixin(Protocol):
	def _audit_software_on_client_insert(
		self: BackendProtocol,
		audit_software_on_clients: list[dict] | list[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient,
		ace: list[RPCACE],
		create: bool,
		set_null: bool,
	) -> None:
		for audit_software_on_client in forceList(audit_software_on_clients):
			if not isinstance(audit_software_on_client, AuditSoftwareOnClient):
				audit_software_on_client = AuditSoftwareOnClient.fromHash(audit_software_on_client)

			software_id, client_id = None, None
			with self._mysql.session() as session:
				res = session.execute(
					"""
				SELECT
					s.`software_id`,
					c.`clientId`
				FROM
					`SOFTWARE` AS s
				LEFT JOIN
					`SOFTWARE_CONFIG` AS c ON c.`software_id` = s.`software_id` AND c.`clientId` = :clientId
				WHERE
					s.`name` = :name AND
					s.`version` = :version AND
					s.`subVersion` = :subVersion AND
					s.`language` = :language AND
					s.`architecture` = :architecture
				""",
					{
						"name": audit_software_on_client.name,
						"version": audit_software_on_client.version,
						"subVersion": audit_software_on_client.subVersion,
						"language": audit_software_on_client.language,
						"architecture": audit_software_on_client.architecture,
						"clientId": audit_software_on_client.clientId,
					},
				).fetchone()
				if res:
					software_id, client_id = res

			if software_id is None:
				if not create:
					return
				raise BackendReferentialIntegrityError(f"Software not found for {audit_software_on_client!r}")

			if client_id or create:
				self._mysql.insert_object(
					table="SOFTWARE_CONFIG",
					obj=audit_software_on_client,
					ace=ace,
					create=not client_id,
					set_null=set_null,
					additional_data={"software_id": software_id},
				)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_insertObject(self: BackendProtocol, auditSoftwareOnClient: dict | AuditSoftwareOnClient) -> None:
		ace = self._get_ace("auditSoftwareOnClient_insertObject")
		self._audit_software_on_client_insert(audit_software_on_clients=auditSoftwareOnClient, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_updateObject(self: BackendProtocol, auditSoftwareOnClient: dict | AuditSoftwareOnClient) -> None:
		ace = self._get_ace("auditSoftwareOnClient_updateObject")
		self._audit_software_on_client_insert(audit_software_on_clients=auditSoftwareOnClient, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_createObjects(
		self: BackendProtocol, auditSoftwareOnClients: list[dict] | list[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_createObjects")
		self._audit_software_on_client_insert(audit_software_on_clients=auditSoftwareOnClients, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_updateObjects(
		self: BackendProtocol, auditSoftwareOnClients: list[dict] | list[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		ace = self._get_ace("auditSoftwareOnClient_updateObjects")
		self._audit_software_on_client_insert(audit_software_on_clients=auditSoftwareOnClients, ace=ace, create=True, set_null=False)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[AuditSoftwareOnClient]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_objects(
			table="`SOFTWARE_CONFIG` JOIN `SOFTWARE` ON `SOFTWARE_CONFIG`.`software_id` = `SOFTWARE`.`software_id`",
			ace=ace,
			object_type=AuditSoftwareOnClient,
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(deprecated=True, alternative_method="auditSoftwareOnClient_getObjects", check_acl=False)
	def auditSoftwareOnClient_getHashes(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[dict]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_objects(
			table="`SOFTWARE_CONFIG` JOIN `SOFTWARE` ON `SOFTWARE_CONFIG`.`software_id` = `SOFTWARE`.`software_id`",
			object_type=AuditSoftwareOnClient,
			ace=ace,
			return_type="dict",
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("auditSoftwareOnClient_getObjects")
		return self._mysql.get_idents(
			table="`SOFTWARE_CONFIG` JOIN `SOFTWARE` ON `SOFTWARE_CONFIG`.`software_id` = `SOFTWARE`.`software_id`",
			object_type=AuditSoftwareOnClient,
			ace=ace,
			ident_type=returnType,
			filter=filter,
		)

	@rpc_method(check_acl=True)
	def auditSoftwareOnClient_deleteObjects(
		self: BackendProtocol, auditSoftwareOnClients: list[dict] | list[AuditSoftwareOnClient] | dict | AuditSoftwareOnClient
	) -> None:
		if not auditSoftwareOnClients:
			return
		for audit_software_on_client in forceList(auditSoftwareOnClients):
			if not isinstance(audit_software_on_client, AuditSoftwareOnClient):
				audit_software_on_client = AuditSoftwareOnClient.fromHash(audit_software_on_client)
			with self._mysql.session() as session:
				session.execute(
					"""
					DELETE
						c.*
					FROM
						`SOFTWARE_CONFIG` AS c JOIN `SOFTWARE` AS s ON c.`software_id` = s.`software_id` AND c.`clientId` = :clientId
					WHERE
						s.name = :name AND
						s.version = :version AND
						s.subVersion = :subVersion AND
						s.language = :language AND
						s.architecture = :architecture
					""",
					{
						"clientId": audit_software_on_client.clientId,
						"name": audit_software_on_client.name,
						"version": audit_software_on_client.version,
						"subVersion": audit_software_on_client.subVersion,
						"language": audit_software_on_client.language,
						"architecture": audit_software_on_client.architecture,
					},
				)

	@rpc_method(check_acl=False)
	def auditSoftwareOnClient_create(
		self: BackendProtocol,
		name: str,
		version: str,
		subVersion: str,
		language: str,
		architecture: str,
		clientId: str,
		uninstallString: str | None = None,
		binaryName: str | None = None,
		firstseen: str | None = None,
		lastseen: str | None = None,
		state: int | None = None,
		usageFrequency: int | None = None,
		lastUsed: str | None = None,
		licenseKey: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		return self.auditSoftwareOnClient_createObjects(AuditSoftwareOnClient.fromHash(_hash))

	def auditSoftwareOnClient_delete(
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
	def auditSoftwareOnClient_setObsolete(self: BackendProtocol, clientId: list[str] | str) -> None:
		with self._mysql.session() as session:
			session.execute("DELETE FROM `SOFTWARE_CONFIG` WHERE `clientId` in :client_ids", params={"client_ids": forceList(clientId)})
