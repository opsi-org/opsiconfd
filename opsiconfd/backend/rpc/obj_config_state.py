# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.config_state
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Protocol

from opsicommon.objects import ConfigState  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCConfigStateMixin(Protocol):
	def _get_config_state_values_with_defaults(self: BackendProtocol, config_ids: List[str], object_id: str) -> Dict[str, List[Any]]:
		res: Dict[str, List[Any]] = {config.id: config.defaultValues for config in self.config_getObjects(id=config_ids)}
		res.update(
			{
				config_state.configId: config_state.values
				for config_state in self.configState_getObjects(configId=config_ids, objectId=object_id)
			}
		)
		return res

	@rpc_method
	def configState_insertObject(self: BackendProtocol, configState: dict | ConfigState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("configState_insertObject")
		self._mysql.insert_object(table="CONFIG_STATE", obj=configState, ace=ace, create=True, set_null=True)

	@rpc_method
	def configState_updateObject(self: BackendProtocol, configState: dict | ConfigState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("configState_updateObject")
		self._mysql.insert_object(table="CONFIG_STATE", obj=configState, ace=ace, create=False, set_null=False)

	@rpc_method
	def configState_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, configStates: List[dict] | List[ConfigState] | dict | ConfigState
	) -> None:
		ace = self._get_ace("configState_createObjects")
		for config_state in forceList(configStates):
			self._mysql.insert_object(table="CONFIG_STATE", obj=config_state, ace=ace, create=True, set_null=True)

	@rpc_method
	def configState_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, configStates: List[dict] | List[ConfigState] | dict | ConfigState
	) -> None:
		ace = self._get_ace("configState_updateObjects")
		for config_state in forceList(configStates):
			self._mysql.insert_object(table="CONFIG_STATE", obj=config_state, ace=ace, create=True, set_null=False)

	@rpc_method
	def configState_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[ConfigState]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_objects(
			table="CONFIG_STATE", ace=ace, object_type=ConfigState, attributes=attributes, filter=filter
		)

	@rpc_method
	def configState_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_objects(
			table="CONFIG_STATE", object_type=ConfigState, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def configState_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_idents(table="CONFIG_STATE", object_type=ConfigState, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def configState_deleteObjects(self: BackendProtocol, configStates: List[dict] | List[ConfigState] | dict | ConfigState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("configState_deleteObjects")
		self._mysql.delete_objects(table="CONFIG_STATE", object_type=ConfigState, obj=configStates, ace=ace)

	@rpc_method
	def configState_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.config_deleteObjects([{"id": id}])
