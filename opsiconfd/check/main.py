# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
health check
"""

from typing import Iterator

from opsiconfd.check.common import CheckResult, check_manager
from opsiconfd.logging import logger


def health_check(clear_cache: bool = False) -> Iterator[CheckResult]:
	from opsiconfd.check.register import register_checks

	register_checks()
	if not check_manager.check_ids:
		logger.error("No valid checks selected. Please check your configuration.")
		return
	for check in check_manager:
		yield check.run(clear_cache)
