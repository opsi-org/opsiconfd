# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
addon test2
"""

from opsiconfd.addon import Addon

from .const import ADDON_ID, ADDON_NAME, ADDON_VERSION


class FailAddonTest(Addon):
	error  # addon can not be loaded
	id = ADDON_ID
	name = ADDON_NAME
	version = ADDON_VERSION
