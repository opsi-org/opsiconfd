# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
websocket
"""

from __future__ import annotations

from uvicorn.protocols.websockets.wsproto_impl import WSProtocol


# Extend WSProtocol to add peer certificate information to the scope if available.
class WSProtocolOpsiconfd(WSProtocol):
	async def run_asgi(self) -> None:
		if "extensions" not in self.scope:
			self.scope["extensions"] = {}
		ssl_obj = self.transport.get_extra_info("ssl_object")
		if ssl_obj:
			self.scope["extensions"]["peer_cert"] = ssl_obj.getpeercert()
		await super().run_asgi()
