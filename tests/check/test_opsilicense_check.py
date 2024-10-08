# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

from opsiconfd.check.common import check_manager
from opsiconfd.check.opsilicense import OpsiLicenseCheck  # noqa: F401
from tests.utils import cleanup_checks  # noqa: F401


def test_check_licenses() -> None:  # noqa: F811
	check_manager.register(OpsiLicenseCheck())
	result = check_manager.get("opsi_licenses").run(use_cache=False)
	assert result.check_status == "ok"
	assert result.partial_results is not None
