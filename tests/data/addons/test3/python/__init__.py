# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
addon test3
"""

from opsiconfd.addon import Addon

from .const import ADDON_ID, ADDON_NAME, ADDON_VERSION


class FailAddonTest(Addon):
	# addon can not be loaded
	error  # type: ignore[name-defined] # noqa: F821
	id = ADDON_ID
	name = ADDON_NAME
	version = ADDON_VERSION
