# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.config_state
"""

from typing import Any, List

from ..mysql import BackendProtocol
from . import rpc_method

# from opsicommon.objects import ConfigState  # type: ignore[import]


class RPCConfigStateMixin:
	@rpc_method
	def configState_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		return self._mysql.get_objects(table="CONFIG_STATE", ace=self._get_ace("configState_getObjects"), attributes=attributes, filter=filter)
