# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd - addon
"""

from .addon import Addon
from .manager import AddonManager

__all__ = ["Addon", "AddonManager"]
