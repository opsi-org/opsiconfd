# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check addons
"""


import asyncio

from opsiconfd.application.admininterface import _get_failed_addons
from opsiconfd.check.common import CheckResult, CheckStatus


def check_opsi_failed_addons() -> CheckResult:
	"""
	## Check Failed Addons

	Checks if there are any failed addons.
	"""
	result = CheckResult(
		check_id="opsi_failed_addons",
		check_name="OPSI failed addons",
		check_description="Checks if there are any failed addons.",
		message="No errors found while loading addons.",
		check_status=CheckStatus.OK,
		details={},
	)
	try:
		loop = asyncio.get_event_loop()
		failed_addons = loop.run_until_complete(_get_failed_addons())
	except RuntimeError:  # No event loop running
		failed_addons = asyncio.run(_get_failed_addons())
	if failed_addons:
		result.check_status = CheckStatus.ERROR
		result.message = "Errors occurred while loading opsiconfd addons."
		result.details["failed_addons"] = failed_addons
		for addon in failed_addons:
			result.message = result.message + f"\n\t {addon.get('name')}: \n\t ERROR: {addon.get('error')}"

	return result
