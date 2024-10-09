# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from typing import Iterator

from opsiconfd.check.common import CheckResult, check_manager


def health_check(clear_cache: bool = False) -> Iterator[CheckResult]:
	from opsiconfd.check.register import register_checks

	register_checks()
	for check in check_manager:
		yield check.run(clear_cache)
