# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.config
"""

from __future__ import annotations

from contextlib import nullcontext
from typing import TYPE_CHECKING, Any, Literal, Protocol

from opsi.opsi.service.model.object import AuditLogEventType, BoolConfig, Config, UnicodeConfig
from opsi.opsi.service.model.type import to_list, to_object_class, to_object_class_list
from starlette.concurrency import run_in_threadpool

from opsiconfd import contextvar_client_session
from opsiconfd.audit_log import audit_log_event_enabled, host_parameter_audit_log
from opsiconfd.auth.role import Role
from opsiconfd.auth.user import create_user_roles, get_users
from opsiconfd.logging import logger
from opsiconfd.messagebus.redis import get_websocket_connected_users
from opsiconfd.utils import asyncio_create_task

from ..auth import RPCACE
from ..mysql.cleanup import remove_orphans_config_state
from . import rpc_method

if TYPE_CHECKING:
	from ..mysql import MySQLSession
	from .protocol import BackendProtocol, IdentType


class RPCConfigMixin(Protocol):
	def _config_default_value_supplied(self: BackendProtocol, config: dict | Config) -> bool:
		if isinstance(config, dict):
			return config.get("defaultValues") is not None
		return config.defaultValues is not None

	def _config_to_objects_with_host_parameter_audit_candidates(
		self: BackendProtocol, configs: list[dict] | list[Config] | dict | Config
	) -> tuple[list[Config], list[Config]]:
		raw_configs = to_list(configs)
		default_values_supplied = [self._config_default_value_supplied(config) for config in raw_configs]
		config_objects = to_object_class_list(raw_configs, Config)
		return config_objects, [config for config, supplied in zip(config_objects, default_values_supplied) if supplied]

	def _config_audit_default_server_value_set(self: BackendProtocol, configs: list[Config]) -> None:
		if not configs or not audit_log_event_enabled(AuditLogEventType.HOST_PARAMETER_VALUE_SET):
			return

		session = contextvar_client_session.get()
		audit_logs = [
			host_parameter_audit_log(
				event_type=AuditLogEventType.HOST_PARAMETER_VALUE_SET,
				entity="default/server",
				config_id=config.id,
				new_value=config.defaultValues,
				session=session,
			)
			for config in configs
		]
		try:
			self.auditLog_bulkInsertObjects(audit_logs)
		except Exception as err:
			logger.error("Failed to write HostParameter default/server audit log: %s", err, exc_info=True)

	def _config_insert_object(
		self: BackendProtocol,
		config: Config | dict,
		ace: list[RPCACE],
		create: bool = True,
		set_null: bool = True,
		session: MySQLSession | None = None,
		lock: bool = True,
	) -> None:
		config = to_object_class(config, Config)
		query, data = self._mysql.insert_query(table="CONFIG", obj=config, ace=ace, create=create, set_null=set_null)
		modify_values = create or data.get("possibleValues") is not None
		with self._mysql.session(session) as session:  # noqa
			with self._mysql.table_lock(session, {"CONFIG": "WRITE", "CONFIG_VALUE": "WRITE"}) if lock else nullcontext():
				if modify_values:
					session.execute("DELETE FROM `CONFIG_VALUE` WHERE configId = :id", params=data)
				if session.execute(query, params=data).rowcount > 0 and modify_values:  # ty: ignore[unresolved-attribute]
					for value in data["possibleValues"] or []:
						session.execute(
							"INSERT INTO `CONFIG_VALUE` (configId, value, isDefault) VALUES (:configId, :value, :isDefault)",
							params={"configId": data["id"], "value": value, "isDefault": value in (data["defaultValues"] or [])},
						)

	@rpc_method(check_acl=False)
	def config_insertObject(self: BackendProtocol, config: dict | Config) -> None:
		ace = self._get_ace("config_insertObject")
		configs, audit_candidates = self._config_to_objects_with_host_parameter_audit_candidates(config)
		config = configs[0]
		self._config_insert_object(config=config, ace=ace, create=True, set_null=True)
		if audit_candidates:
			self._config_audit_default_server_value_set(audit_candidates)
		if not self.events_enabled:
			return
		self._send_messagebus_event("config_created", data=config.getIdent("dict"))  # ty: ignore[invalid-argument-type]

	@rpc_method(check_acl=False)
	def config_updateObject(self: BackendProtocol, config: dict | Config) -> None:
		ace = self._get_ace("config_updateObject")
		configs, audit_candidates = self._config_to_objects_with_host_parameter_audit_candidates(config)
		config = configs[0]
		self._config_insert_object(config=config, ace=ace, create=False, set_null=False)
		if audit_candidates:
			self._config_audit_default_server_value_set(audit_candidates)
		if not self.events_enabled:
			return
		self._send_messagebus_event("config_updated", data=config.getIdent("dict"))  # ty: ignore[invalid-argument-type]

	@rpc_method(check_acl=False)
	def config_createObjects(self: BackendProtocol, configs: list[dict] | list[Config] | dict | Config) -> None:
		ace = self._get_ace("config_createObjects")
		configs, audit_candidates = self._config_to_objects_with_host_parameter_audit_candidates(configs)
		with self._mysql.session() as session, self._mysql.table_lock(session, {"CONFIG": "WRITE", "CONFIG_VALUE": "WRITE"}):
			for config in configs:
				self._config_insert_object(config=config, ace=ace, create=True, set_null=True, session=session, lock=False)
		if audit_candidates:
			self._config_audit_default_server_value_set(audit_candidates)
		if not self.events_enabled:
			return
		for config in configs:
			self._send_messagebus_event("config_created", data=config.getIdent("dict"))  # ty: ignore[invalid-argument-type]

	@rpc_method(check_acl=False)
	def config_updateObjects(self: BackendProtocol, configs: list[dict] | list[Config] | dict | Config) -> None:
		ace = self._get_ace("config_updateObjects")
		configs, audit_candidates = self._config_to_objects_with_host_parameter_audit_candidates(configs)
		with self._mysql.session() as session, self._mysql.table_lock(session, {"CONFIG": "WRITE", "CONFIG_VALUE": "WRITE"}):
			for config in configs:
				self._config_insert_object(config=config, ace=ace, create=True, set_null=False, session=session, lock=False)
		if audit_candidates:
			self._config_audit_default_server_value_set(audit_candidates)
		if not self.events_enabled:
			return
		for config in configs:
			self._send_messagebus_event("config_updated", data=config.getIdent("dict"))  # ty: ignore[invalid-argument-type]

	def _config_get(
		self: BackendProtocol,
		ace: list[RPCACE] | None = None,
		return_type: Literal["object", "dict"] = "object",
		attributes: list[str] | tuple[str, ...] | None = None,
		filter: dict[str, Any] | None = None,
	) -> list[dict] | list[Config]:
		aggregates = {
			"possibleValues": f'GROUP_CONCAT(`value` SEPARATOR "{self._mysql.record_separator}")',
			"defaultValues": f'GROUP_CONCAT(IF(`isDefault`, `value`, NULL) SEPARATOR "{self._mysql.record_separator}")',
		}
		return self._mysql.get_objects(
			table="CONFIG LEFT JOIN CONFIG_VALUE ON CONFIG.configId = CONFIG_VALUE.configId",
			object_type=Config,
			aggregates=aggregates,
			ace=ace,
			return_type=return_type,
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def config_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[Config]:
		ace = self._get_ace("config_getObjects")
		return self._config_get(ace=ace, return_type="object", attributes=attributes, filter=filter)  # ty: ignore[invalid-return-type]

	@rpc_method(deprecated=True, alternative_method="config_getObjects", check_acl=False)
	def config_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("config_getObjects")
		return self._config_get(ace=ace, return_type="dict", attributes=attributes, filter=filter)  # ty: ignore[invalid-return-type]

	@rpc_method(check_acl=False)
	def config_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("config_getObjects")
		return self._mysql.get_idents("CONFIG", Config, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def config_deleteObjects(self: BackendProtocol, configs: list[dict] | list[Config] | dict | Config) -> None:
		if not configs:
			return
		# CONFIG_VALUE will be deleted by CASCADE
		ace = self._get_ace("config_deleteObjects")
		self._mysql.delete_objects(table="CONFIG", object_type=Config, obj=configs, ace=ace)
		with self._mysql.session() as session:
			remove_orphans_config_state(session)
		if not self.events_enabled:
			return
		configs = to_object_class_list(configs, Config)
		for config in configs:
			self._send_messagebus_event("config_deleted", data=config.getIdent("dict"))  # ty: ignore[invalid-argument-type]

	@rpc_method(check_acl=False)
	def config_create(
		self: BackendProtocol,
		id: str,
		description: str | None = None,
		possibleValues: list | None = None,
		defaultValues: list | None = None,
		editable: bool | None = None,
		multiValue: bool | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.config_createObjects(Config.fromHash(_hash))

	@rpc_method(check_acl=False)
	def config_createUnicode(
		self: BackendProtocol,
		id: str,
		description: str | None = None,
		possibleValues: list[str] | None = None,
		defaultValues: list[str] | None = None,
		editable: bool | None = None,
		multiValue: bool | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.config_createObjects(UnicodeConfig.fromHash(_hash))

	@rpc_method(check_acl=False)
	def config_createBool(
		self: BackendProtocol,
		id: str,
		description: str | None = None,
		defaultValues: list[bool] | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.config_createObjects(BoolConfig.fromHash(_hash))

	@rpc_method(check_acl=False)
	def config_delete(self: BackendProtocol, id: list[str] | str) -> None:
		idents = self.config_getIdents(returnType="dict", id=id)
		if idents:
			self.config_deleteObjects(idents)

	@rpc_method(check_acl=False)
	async def config_updateMessageOfTheDay(
		self: BackendProtocol,
		device_message: str | None = None,
		device_message_valid_until: int | None = None,
		user_message: str | None = None,
		user_message_valid_until: int | None = None,
	) -> None:
		self._assert_module("message_of_the_day")

		configs = []
		if device_message is not None:
			configs.append(
				UnicodeConfig(
					id="message_of_the_day.device.message",
					description="Message of the day to show on device when no user is logged in",
					possibleValues=[device_message],
					defaultValues=[device_message],
					editable=True,
					multiValue=False,
				)
			)
		if device_message_valid_until is not None:
			configs.append(
				UnicodeConfig(
					id="message_of_the_day.device.message_valid_until",
					description="Timestamp until the device message of the day is valid",
					possibleValues=[str(int(device_message_valid_until))],
					defaultValues=[str(int(device_message_valid_until))],
					editable=True,
					multiValue=False,
				)
			)
		if user_message is not None:
			configs.append(
				UnicodeConfig(
					id="message_of_the_day.user.message",
					description="Message of the day to show on device when a user is logged in",
					possibleValues=[user_message],
					defaultValues=[user_message],
					editable=True,
					multiValue=False,
				)
			)
		if user_message_valid_until is not None:
			configs.append(
				UnicodeConfig(
					id="message_of_the_day.user.message_valid_until",
					description="Timestamp until the user message of the day is valid",
					possibleValues=[str(int(user_message_valid_until))],
					defaultValues=[str(int(user_message_valid_until))],
					editable=True,
					multiValue=False,
				)
			)
		if configs:
			await run_in_threadpool(self.config_createObjects, configs)
			config_values = {
				config.id: config.defaultValues[0]
				for config in await run_in_threadpool(
					self.config_getObjects,
					id=[
						"message_of_the_day.device.message",
						"message_of_the_day.device.message_valid_until",
						"message_of_the_day.user.message",
						"message_of_the_day.user.message_valid_until",
					],
				)
			}
			client_ids = await get_websocket_connected_users(user_type="client")
			logger.info("Sending messageOfTheDayUpdated to %d messagebus connected clients", len(client_ids))
			if client_ids:
				asyncio_create_task(
					self._messagebus_rpc(
						client_ids=client_ids,
						method="messageOfTheDayUpdated",
						params=[
							config_values.get("message_of_the_day.device.message") or "",
							int(config_values.get("message_of_the_day.device.message_valid_until") or "0"),
							config_values.get("message_of_the_day.user.message") or "",
							int(config_values.get("message_of_the_day.user.message_valid_until") or "0"),
						],
						timeout=5,
						messagebus_only=True,
					)
				)

	@rpc_method(check_acl=False)
	def config_createRole(self: BackendProtocol, name: str) -> None:
		Role(name=name)
		users = get_users()
		for user in users:
			create_user_roles(user)
