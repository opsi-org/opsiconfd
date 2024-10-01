# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import opsiconfd.check.opsilicense  # noqa: F401
from opsiconfd.check.common import check_manager


def test_check_licenses() -> None:  # noqa: F811
	result = check_manager.get("opsi_licenses").run(use_cache=False)
	assert result.check_status == "ok"
	assert result.partial_results is not None
