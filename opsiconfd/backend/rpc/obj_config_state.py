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

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


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
	def configState_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[ConfigState]:  # pylint: disable=redefined-builtin,invalid-name
		return self._mysql.get_objects(
			table="CONFIG_STATE", ace=self._get_ace("configState_getObjects"), object_type=ConfigState, attributes=attributes, filter=filter
		)
