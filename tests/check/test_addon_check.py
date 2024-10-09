# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import os

from _pytest.fixtures import FixtureFunction

import opsiconfd.check.addon  # noqa: F401
from opsiconfd.addon.manager import AddonManager
from opsiconfd.check.common import CheckStatus, check_manager
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import Config
from tests.utils import (
	config as test_config,  # noqa: F401
)


def test_check_opsi_failed_addons(test_config: Config, cleanup: FixtureFunction) -> None:  # noqa: F811
	test_config.addon_dirs = [os.path.abspath("tests/data/addons")]

	addon_manager = AddonManager()
	addon_manager.load_addons()

	result = check_manager.get("opsi_failed_addons").run(clear_cache=True)
	assert result.check_status == CheckStatus.ERROR

	test_config.addon_dirs = []

	addon_manager = AddonManager()
	addon_manager.load_addons()

	result = check_manager.get("opsi_failed_addons").run(clear_cache=True)
	assert result.check_status == CheckStatus.OK
