# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
addon test1
"""

from opsiconfd.addon import Addon

class AddonTest1(Addon):
	id = "test2"
	name = "Test-Addon #2"
	version = "1.1"

	def on_load(self, app):  # pylint: disable=no-self-use
		"""Called after loading the addon"""
		return

	def on_unload(self, app):  # pylint: disable=no-self-use
		"""Called before unloading the addon"""
		return
