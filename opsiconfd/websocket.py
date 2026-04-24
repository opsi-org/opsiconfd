# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
websocket
"""

from __future__ import annotations

from asyncio.events import AbstractEventLoop
from typing import Any

from uvicorn.config import Config
from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol
from uvicorn.protocols.websockets.wsproto_impl import WSProtocol
from uvicorn.server import ServerState

from opsiconfd.config import config as opsiconfd_config


# Extend WebSocketProtocol to set the open_timeout from opsiconfd_config.
class WebSocketProtocolOpsiconfd(WebSocketProtocol):
	def __init__(
		self, config: Config, server_state: ServerState, app_state: dict[str, Any], _loop: AbstractEventLoop | None = None
	) -> None:
		super().__init__(config, server_state, app_state, _loop)
		self.open_timeout = opsiconfd_config.websocket_open_timeout


# Extend WSProtocol to add peer certificate information to the scope if available.
class WSProtocolOpsiconfd(WSProtocol):
	async def run_asgi(self) -> None:
		if "extensions" not in self.scope:
			self.scope["extensions"] = {}
		ssl_obj = self.transport.get_extra_info("ssl_object")
		if ssl_obj:
			self.scope["extensions"]["peer_cert"] = ssl_obj.getpeercert()
		await super().run_asgi()
