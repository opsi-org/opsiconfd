# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - addon
"""

from fastapi import FastAPI

class Addon:
	id = None  # pylint: disable=invalid-name
	name = None
	version = None

	def __init__(self, path: str) -> None:  # pylint: disable=redefined-builtin
		self.path = path

	@property
	def router_prefix(self):
		return f"/addons/{self.id}"

	def on_load(self, app: FastAPI) -> None:  # pylint: disable=no-self-use,unused-argument
		"""Called after loading the addon"""
		return

	def on_unload(self, app: FastAPI) -> None:  # pylint: disable=no-self-use,unused-argument
		"""Called before unloading the addon"""
		return

	#def on_application_setup(self, app: FastAPI) -> None:  # pylint: disable=no-self-use,unused-argument
	#	"""Called on application setup"""
	#	return
