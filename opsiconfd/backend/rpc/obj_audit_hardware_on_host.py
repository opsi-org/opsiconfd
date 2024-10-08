# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.audit_hardware_on_host
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Literal, Protocol

from opsicommon.exceptions import BackendPermissionDeniedError
from opsicommon.objects import (
	AuditHardware,
	AuditHardwareOnHost,
)
from opsicommon.types import forceList

from opsiconfd.logging import logger

from ..auth import RPCACE, RPCACE_ALLOW_ALL
from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCAuditHardwareOnHostMixin(Protocol):
	def _audit_hardware_on_host_by_hardware_class(
		self: BackendProtocol, audit_hardware_on_hosts: list[dict] | list[AuditHardwareOnHost] | dict | AuditHardwareOnHost
	) -> dict[str, list[AuditHardwareOnHost]]:
		by_hardware_class = defaultdict(list)
		for ahoh in forceList(audit_hardware_on_hosts):
			if not isinstance(ahoh, AuditHardwareOnHost):
				ahoh = AuditHardwareOnHost.fromHash(ahoh)
			by_hardware_class[ahoh.hardwareClass].append(ahoh)
		return by_hardware_class

	def _audit_hardware_on_host_to_audit_hardware(
		self: BackendProtocol, audit_hardware_on_host: dict | AuditHardwareOnHost
	) -> AuditHardware:
		if isinstance(audit_hardware_on_host, AuditHardwareOnHost):
			return AuditHardware.fromHash(audit_hardware_on_host.to_hash())
		return AuditHardware.fromHash(audit_hardware_on_host)

	def _audit_hardware_on_host_insert(
		self: BackendProtocol,
		audit_hardware_on_hosts: list[dict] | list[AuditHardwareOnHost] | dict | AuditHardwareOnHost,
		ace: list[RPCACE],
		create: bool,
		set_null: bool,
	) -> None:
		for hardware_class, ahohs in self._audit_hardware_on_host_by_hardware_class(audit_hardware_on_hosts).items():
			audit_hardware_indent_attributes = set(AuditHardware.hardware_attributes[hardware_class])
			ahoh_only_ident_attributes = set(AuditHardwareOnHost.hardware_attributes[hardware_class]) - audit_hardware_indent_attributes
			ahoh_only_ident_attributes.add("hostId")

			for audit_hardware_on_host in ahohs:
				audit_hardware = self._audit_hardware_on_host_to_audit_hardware(audit_hardware_on_host)
				hardware_id, config_id = None, None
				with self._mysql.session() as session:
					params: dict[str, Any] = {}

					conditions = []
					for attr in audit_hardware_indent_attributes:
						val = getattr(audit_hardware, attr)
						param = f"p{len(params) + 1}"
						params[param] = val
						conditions.append(f"`hd`.`{attr}` {'IS' if val is None else '='} :{param}")

					join_conditions = ["`hd`.`hardware_id` = `hc`.`hardware_id`"]
					for attr in ahoh_only_ident_attributes:
						val = getattr(audit_hardware_on_host, attr)
						param = f"p{len(params) + 1}"
						params[param] = val
						join_conditions.append(f"`hc`.`{attr}` {'IS' if val is None else '='} :{param}")

					query = (
						f"SELECT hd.hardware_id, hc.config_id"
						f" FROM HARDWARE_DEVICE_{hardware_class.upper()} AS hd LEFT JOIN HARDWARE_CONFIG_{hardware_class.upper()} AS hc"
						f" ON {' AND '.join(join_conditions)}"
						f" WHERE {' AND '.join(conditions)}"
					)
					res = session.execute(query, params=params).fetchone()

					if res:
						hardware_id, config_id = res

				logger.debug(
					"hardware_class: %r, hardware_id: %r, config_id: %r, create: %r", hardware_class, hardware_id, config_id, create
				)
				if not hardware_id:
					if not create:
						continue
					hardware_id = self._mysql.insert_object(
						table=f"HARDWARE_DEVICE_{hardware_class.upper()}",
						obj=audit_hardware,
						ace=[RPCACE_ALLOW_ALL],
						create=True,
						set_null=True,
					)

				if config_id or create:
					# Create only if not exists (ON DUPLICATE KEY will not work!)
					self._mysql.insert_object(
						table=f"HARDWARE_CONFIG_{hardware_class.upper()}",
						obj=audit_hardware_on_host,
						ace=ace,
						create=not config_id,
						set_null=set_null,
						additional_data={"hardware_id": hardware_id},
					)

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_insertObject(self: BackendProtocol, auditHardwareOnHost: dict | AuditHardwareOnHost) -> None:
		ace = self._get_ace("auditHardwareOnHost_insertObject")
		self._audit_hardware_on_host_insert(audit_hardware_on_hosts=auditHardwareOnHost, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_updateObject(self: BackendProtocol, auditHardwareOnHost: dict | AuditHardwareOnHost) -> None:
		ace = self._get_ace("auditHardwareOnHost_updateObject")
		self._audit_hardware_on_host_insert(audit_hardware_on_hosts=auditHardwareOnHost, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_createObjects(
		self: BackendProtocol, auditHardwareOnHosts: list[dict] | list[AuditHardwareOnHost] | dict | AuditHardwareOnHost
	) -> None:
		ace = self._get_ace("auditHardwareOnHost_createObjects")
		self._audit_hardware_on_host_insert(audit_hardware_on_hosts=auditHardwareOnHosts, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_updateObjects(
		self: BackendProtocol, auditHardwareOnHosts: list[dict] | list[AuditHardwareOnHost] | dict | AuditHardwareOnHost
	) -> None:
		ace = self._get_ace("auditHardwareOnHost_updateObjects")
		self._audit_hardware_on_host_insert(audit_hardware_on_hosts=auditHardwareOnHosts, ace=ace, create=True, set_null=False)

	def _audit_hardware_on_host_get(
		self: BackendProtocol,
		ace: list[RPCACE],
		return_hardware_ids: bool = False,
		return_type: Literal["object", "dict", "ident"] = "object",
		ident_type: IdentType = "str",
		attributes: list[str] | None = None,
		filter: dict[str, Any] | None = None,
	) -> list[AuditHardwareOnHost | str | dict[str, Any] | list[Any] | tuple[Any, ...]] | list:
		attributes = attributes or []
		filter = filter or {}
		hardware_classes = set()
		hardware_class = filter.get("hardwareClass")
		if hardware_class not in ([], None):
			for hwc in forceList(hardware_class):
				regex = re.compile(f"^{hwc.replace('*', '.*')}$")
				for key in self._audit_hardware_database_config:
					if regex.search(key):
						hardware_classes.add(key)

			if not hardware_classes:
				return []

		if not hardware_classes:
			hardware_classes = set(self._audit_hardware_database_config)

		for unwanted_key in ("hardwareClass", "type"):
			try:
				del filter[unwanted_key]
			except KeyError:
				pass  # not there - everything okay.

		if return_hardware_ids and attributes and "hardware_id" not in attributes:
			attributes.append("hardware_id")

		results: list[AuditHardwareOnHost | str | dict[str, Any] | list[Any] | tuple[Any, ...]] | list = []
		with self._mysql.session() as session:
			for hardware_class in hardware_classes:
				class_filter = {}
				ident_attributes = []
				for attr, info in self._audit_hardware_database_config[hardware_class].items():
					if info.get("Scope") == "g":
						ident_attributes.append(attr)
					if attr in filter:
						class_filter[attr] = ["", None] if filter[attr] in ("", None) else filter[attr]
					if attributes and attr not in attributes:
						attributes.append(attr)

				for attr in ("hostId", "state", "firstseen", "lastseen"):
					if attr in filter:
						class_filter[attr] = filter[attr]
					if attributes and attr not in attributes:
						attributes.append(attr)

				if attributes and return_hardware_ids and "hardware_id" not in attributes:
					attributes.append("hardware_id")

				if return_type == "ident":
					attributes = ident_attributes

				if not class_filter and filter:
					continue

				device_table = f"HARDWARE_DEVICE_{hardware_class.upper()}"
				config_table = f"HARDWARE_CONFIG_{hardware_class.upper()}"
				columns = self._mysql.get_columns(tables=[device_table, config_table], ace=ace, attributes=attributes)

				if not return_hardware_ids and "hardware_id" in columns:
					del columns["hardware_id"]
				where, params = self._mysql.get_where(columns=columns, ace=ace, filter=class_filter)
				query = (
					f"""SELECT {', '.join([f"{c.select} AS `{a}`" for a, c in columns.items() if c.select])} FROM `{device_table}` """
					f"""JOIN `{config_table}` ON `{config_table}`.`hardware_id` = `{device_table}`.`hardware_id` {where}"""
				)
				for row in session.execute(query, params=params).fetchall():
					data = dict(row)
					if return_type == "object":
						results.append(AuditHardwareOnHost(hardwareClass=hardware_class, **data))
					elif return_type == "ident":
						results.append(self._mysql.get_ident(data=data, ident_attributes=ident_attributes, ident_type=ident_type))
					else:
						results.append(data)
		return results

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_getObjects(
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[AuditHardwareOnHost]:
		ace = self._get_ace("auditHardwareOnHost_getObjects")
		return self._audit_hardware_on_host_get(
			ace=ace, return_hardware_ids=False, return_type="object", attributes=attributes, filter=filter
		)  # type: ignore[return-value]

	@rpc_method(deprecated=True, alternative_method="auditHardwareOnHost_getObjects", check_acl=False)
	def auditHardwareOnHost_getHashes(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[dict]:
		ace = self._get_ace("auditHardwareOnHost_getObjects")
		return self._audit_hardware_on_host_get(
			ace=ace, return_hardware_ids=False, return_type="dict", attributes=attributes, filter=filter
		)  # type: ignore[return-value]

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("auditHardwareOnHost_getObjects")
		return self._audit_hardware_on_host_get(
			ace=ace, return_hardware_ids=False, return_type="ident", ident_type=returnType, filter=filter
		)  # type: ignore[return-value]

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_deleteObjects(
		self: BackendProtocol, auditHardwareOnHosts: list[dict] | list[AuditHardwareOnHost] | dict | AuditHardwareOnHost
	) -> None:
		if not auditHardwareOnHosts:
			return
		ace = self._get_ace("auditHardwareOnHost_deleteObjects")
		allowed_client_ids = self._mysql.get_allowed_client_ids(ace)
		with self._mysql.session() as session:
			for hardware_class, ahohs in self._audit_hardware_on_host_by_hardware_class(auditHardwareOnHosts).items():
				audit_hardware_indent_attributes = set(AuditHardware.hardware_attributes[hardware_class])
				ahoh_only_ident_attributes = set(AuditHardwareOnHost.hardware_attributes[hardware_class]) - audit_hardware_indent_attributes
				ahoh_only_ident_attributes.add("hostId")

				conditions = []
				params: dict[str, Any] = {}
				for ahoh in ahohs:
					if allowed_client_ids and ahoh.hostId not in allowed_client_ids:
						raise BackendPermissionDeniedError("Delete permission denied")

					cond = []
					for attr in ahoh_only_ident_attributes:
						val = getattr(ahoh, attr)
						param = f"p{len(params) + 1}"
						params[param] = val
						cond.append(f"`{attr}` {'IS' if val is None else '='} :{param}")
					conditions.append(f"({' AND '.join(cond)})")

				query = f"DELETE FROM HARDWARE_CONFIG_{hardware_class.upper()} WHERE {' OR '.join(conditions)}"
				session.execute(query, params=params)

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_create(
		self: BackendProtocol,
		hostId: str,
		hardwareClass: str,
		firstseen: str | None = None,
		lastseen: str | None = None,
		state: int | None = None,
		**kwargs: Any,
	) -> None:
		_hash = locals()
		del _hash["self"]
		return self.auditHardwareOnHost_createObjects(AuditHardwareOnHost.fromHash(_hash))

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_delete(
		self: BackendProtocol,
		hostId: str,
		hardwareClass: str,
		firstseen: str | list[str] | None = None,
		lastseen: str | list[str] | None = None,
		state: int | list[int] | None = None,
		**kwargs: Any,
	) -> None:
		if hostId is None:
			hostId = []
		if hardwareClass is None:
			hardwareClass = []
		if firstseen is None:
			firstseen = []
		if lastseen is None:
			lastseen = []
		if state is None:
			state = []

		kwargs = {key: [] if val is None else val for key, val in kwargs.items()}

		objs = self.auditHardwareOnHost_getObjects(
			hostId=hostId, hardwareClass=hardwareClass, firstseen=firstseen, lastseen=lastseen, state=state, **kwargs
		)
		if objs:
			self.auditHardwareOnHost_deleteObjects(objs)

	@rpc_method(check_acl=False)
	def auditHardwareOnHost_setObsolete(self, hostId: str) -> None:
		self.auditHardwareOnHost_deleteObjects(self.auditHardwareOnHost_getObjects(hostId=hostId))
