# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.config
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Literal, Protocol, Tuple

from opsicommon.objects import Config  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from ..auth import RPCACE
from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCConfigMixin(Protocol):
	def _config_insert_object(
		self: BackendProtocol, config: Config, ace: List[RPCACE], create: bool = True, set_null: bool = True
	) -> None:
		query, data = self._mysql.insert_query(table="CONFIG", obj=config, ace=ace, create=create, set_null=set_null)
		with self._mysql.session() as session:
			session.execute("DELETE FROM `CONFIG_VALUE` WHERE configId = :id", params=data)
			if session.execute(query, params=data).rowcount > 0:
				for value in data["possibleValues"] or []:
					session.execute(
						"INSERT INTO `CONFIG_VALUE` (configId, value, isDefault) VALUES (:configId, :value, :isDefault)",
						params={"configId": data["id"], "value": value, "isDefault": value in (data["defaultValues"] or [])}  # pylint: disable=loop-invariant-statement
					)

	@rpc_method
	def config_insertObject(self: BackendProtocol, config: dict | Config) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("config_insertObject")
		self._config_insert_object(config=config, ace=ace, create=True, set_null=True)

	@rpc_method
	def config_updateObject(self: BackendProtocol, config: dict | Config) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("config_updateObject")
		self._config_insert_object(config=config, ace=ace, create=False, set_null=False)

	@rpc_method
	def config_createObjects(self: BackendProtocol, configs: List[dict] | List[Config] | dict | Config) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("config_createObjects")
		for config in forceList(configs):
			self._config_insert_object(config=config, ace=ace, create=True, set_null=True)

	@rpc_method
	def config_updateObjects(self: BackendProtocol, configs: List[dict] | List[Config] | dict | Config) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("config_updateObjects")
		for config in forceList(configs):
			self._config_insert_object(config=config, ace=ace, create=True, set_null=False)

	def _config_get(  # pylint: disable=too-many-arguments,too-many-locals
		self: BackendProtocol,
		ace: List[RPCACE] = None,
		return_type: Literal["object", "dict"] = "object",
		attributes: List[str] | Tuple[str, ...] | None = None,
		filter: Dict[str, Any] = None,  # pylint: disable=redefined-builtin
	) -> List[dict] | List[Config]:
		aggregates = {
			"possibleValues": f'GROUP_CONCAT(`value` SEPARATOR "{self._mysql.record_separator}")',
			"defaultValues": f'GROUP_CONCAT(IF(`isDefault`, `value`, NULL) SEPARATOR "{self._mysql.record_separator}")'
		}
		return self._mysql.get_objects(
			table="CONFIG LEFT JOIN CONFIG_VALUE ON CONFIG.configId = CONFIG_VALUE.configId",
			object_type=Config,
			aggregates=aggregates,
			ace=ace,
			return_type=return_type,
			attributes=attributes,
			filter=filter
		)

	@rpc_method
	def config_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[Config]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("config_getObjects")
		return self._config_get(ace=ace, return_type="object", attributes=attributes, filter=filter)

	@rpc_method
	def config_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("config_getObjects")
		return self._config_get(ace=ace, return_type="dict", attributes=attributes, filter=filter)

	@rpc_method
	def config_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("config_getObjects")
		return self._mysql.get_idents("CONFIG", Config, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def config_deleteObjects(self: BackendProtocol, configs: List[dict] | List[Config] | dict | Config) -> None:  # pylint: disable=invalid-name
		# CONFIG_VALUE will be deleted by CASCADE
		ace = self._get_ace("config_deleteObjects")
		self._mysql.delete_query(table="CONFIG", object_type=Config, obj=configs, ace=ace)

	@rpc_method
	def config_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.config_deleteObjects([{"id": id}])
