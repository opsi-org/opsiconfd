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


# TODO: Remove
class WSProtocolOpsiconfd(WSProtocol):
	pass
