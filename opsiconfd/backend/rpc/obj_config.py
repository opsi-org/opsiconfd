# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.config
"""
from __future__ import annotations

from contextlib import nullcontext
from typing import TYPE_CHECKING, Any, Literal, Protocol

from opsicommon.objects import BoolConfig, Config, UnicodeConfig
from opsicommon.types import forceObjectClass, forceObjectClassList
from starlette.concurrency import run_in_threadpool

from opsiconfd.messagebus.redis import get_websocket_connected_users

from ..auth import RPCACE
from ..mysql.cleanup import remove_orphans_config_state
from . import rpc_method

if TYPE_CHECKING:
	from ..mysql import Session
	from .protocol import BackendProtocol, IdentType


class RPCConfigMixin(Protocol):
	def _config_insert_object(
		self: BackendProtocol,
		config: Config | dict,
		ace: list[RPCACE],
		create: bool = True,
		set_null: bool = True,
		session: Session | None = None,
		lock: bool = True,
	) -> None:
		config = forceObjectClass(config, Config)
		query, data = self._mysql.insert_query(table="CONFIG", obj=config, ace=ace, create=create, set_null=set_null)
		with self._mysql.session(session) as session:
			with self._mysql.table_lock(session, {"CONFIG": "WRITE", "CONFIG_VALUE": "WRITE"}) if lock else nullcontext():
				session.execute("DELETE FROM `CONFIG_VALUE` WHERE configId = :id", params=data)
				if session.execute(query, params=data).rowcount > 0:
					for value in data["possibleValues"] or []:
						session.execute(
							"INSERT INTO `CONFIG_VALUE` (configId, value, isDefault) VALUES (:configId, :value, :isDefault)",
							params={"configId": data["id"], "value": value, "isDefault": value in (data["defaultValues"] or [])},
						)

	@rpc_method(check_acl=False)
	def config_insertObject(self: BackendProtocol, config: dict | Config) -> None:
		ace = self._get_ace("config_insertObject")
		config = forceObjectClass(config, Config)
		self._config_insert_object(config=config, ace=ace, create=True, set_null=True)
		if not self.events_enabled:
			return
		self._send_messagebus_event("config_created", data=config.getIdent("dict"))  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def config_updateObject(self: BackendProtocol, config: dict | Config) -> None:
		ace = self._get_ace("config_updateObject")
		config = forceObjectClass(config, Config)
		self._config_insert_object(config=config, ace=ace, create=False, set_null=False)
		if not self.events_enabled:
			return
		self._send_messagebus_event("config_updated", data=config.getIdent("dict"))  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def config_createObjects(self: BackendProtocol, configs: list[dict] | list[Config] | dict | Config) -> None:
		ace = self._get_ace("config_createObjects")
		configs = forceObjectClassList(configs, Config)
		with self._mysql.session() as session:
			with self._mysql.table_lock(session, {"CONFIG": "WRITE", "CONFIG_VALUE": "WRITE"}):
				for config in configs:
					self._config_insert_object(config=config, ace=ace, create=True, set_null=True, session=session, lock=False)
		if not self.events_enabled:
			return
		for config in configs:
			self._send_messagebus_event("config_created", data=config.getIdent("dict"))  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def config_updateObjects(self: BackendProtocol, configs: list[dict] | list[Config] | dict | Config) -> None:
		ace = self._get_ace("config_updateObjects")
		configs = forceObjectClassList(configs, Config)
		with self._mysql.session() as session:
			with self._mysql.table_lock(session, {"CONFIG": "WRITE", "CONFIG_VALUE": "WRITE"}):
				for config in configs:
					self._config_insert_object(config=config, ace=ace, create=True, set_null=False, session=session, lock=False)
		if not self.events_enabled:
			return
		for config in configs:
			self._send_messagebus_event("config_updated", data=config.getIdent("dict"))  # type: ignore[arg-type]

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
		return self._config_get(ace=ace, return_type="object", attributes=attributes, filter=filter)  # type: ignore[return-value]

	@rpc_method(deprecated=True, alternative_method="config_getObjects", check_acl=False)
	def config_getHashes(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[dict]:
		ace = self._get_ace("config_getObjects")
		return self._config_get(ace=ace, return_type="dict", attributes=attributes, filter=filter)  # type: ignore[return-value]

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
		configs = forceObjectClassList(configs, Config)
		for config in configs:
			self._send_messagebus_event("config_deleted", data=config.getIdent("dict"))  # type: ignore[arg-type]

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
			client_ids = [client_id async for client_id in get_websocket_connected_users(user_type="client")]
			if client_ids:
				return await self._messagebus_rpc(
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
