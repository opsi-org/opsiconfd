# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check addons
# """

from dataclasses import dataclass

from opsiconfd.application.admininterface import _get_failed_addons
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager


@dataclass()
class AddonCheck(Check):
	id: str = "opsi_failed_addons"
	name: str = "OPSI failed addons"
	description: str = "Checks if there are any failed addons."
	documentation: str = """
	## Check Failed Addons

	Checks if there are any failed addons. If there are any failed addons, the check will return an error and list the failed addons.
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No errors found while loading addons.",
			check_status=CheckStatus.OK,
		)
		failed_addons = _get_failed_addons()
		if failed_addons:
			result.check_status = CheckStatus.ERROR
			result.message = "Errors occurred while loading opsiconfd addons: "
			result.details["failed_addons"] = failed_addons
			for addon in failed_addons:
				result.message = result.message + f"{addon.get('name')} "

		return result


addon_check = AddonCheck()
check_manager.register(addon_check)
