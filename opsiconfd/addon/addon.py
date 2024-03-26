# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd - addon
"""

import os

from fastapi import FastAPI
from fastapi.requests import HTTPConnection
from starlette.types import Receive, Send


class Addon:
	id: str = ""
	name: str = ""
	version: str = ""

	def __init__(self, path: str) -> None:
		self.path = path
		self.data_path = os.path.join(self.path, "data")
		for attr in ("id", "name", "version"):
			if not getattr(self, attr):
				raise ValueError(f"Attribute '{attr}' is not set")

	@property
	def router_prefix(self) -> str:
		return f"/addons/{self.id}"

	def on_load(self, app: FastAPI) -> None:
		"""Called after loading the addon"""
		return

	def on_unload(self, app: FastAPI) -> None:
		"""Called before unloading the addon"""
		return

	async def handle_request(self, connection: HTTPConnection, receive: Receive, send: Send) -> bool:
		"""Called on every request where the path matches the addons router prefix.
		Return true to skip further request processing."""
		return False

	async def handle_request_exception(self, err: Exception, connection: HTTPConnection, receive: Receive, send: Send) -> bool:
		"""Called on every request exception where the path matches the addons router prefix.
		Return true to skip further request processing."""
		return False
