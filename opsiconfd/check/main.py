# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from typing import Iterator


from opsiconfd.check.common import CheckResult, CheckManager
from opsiconfd.check.registry import check_manager


def health_check(use_cache: bool = True) -> Iterator[CheckResult]:
	for check in CheckManager():
		yield check.run(use_cache)
