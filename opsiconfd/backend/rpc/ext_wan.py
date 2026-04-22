# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
rpc methods wan
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from opsi.opsi.service.model.type import to_bool, to_host_id_list

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtWANMixin(Protocol):
	@rpc_method(check_acl=False)
	def changeWANConfig(self: BackendProtocol, boolean: bool, clientIds: list[str]) -> None:
		"""
		Change the WAN configuration.

		:param boolean: Should the WAN config be enabled or not?
		:type boolean: bool
		:param clientIds: The IDs of the clients where the setting should be changed.
		:type clientIDs: [str, ]
		"""
		enabled = to_bool(boolean)

		for client_id in to_host_id_list(clientIds):
			self.configState_create("opsiclientd.event_gui_startup.active", client_id, not enabled)
			self.configState_create("opsiclientd.event_gui_startup{user_logged_in}.active", client_id, not enabled)
			self.configState_create("opsiclientd.event_timer.active", client_id, enabled)
			if not enabled:
				self.configState_create("opsiclientd.event_net_connection.active", client_id, enabled)
