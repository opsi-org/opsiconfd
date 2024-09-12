# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check addons
# """

# from opsiconfd.application.admininterface import _get_failed_addons
# from opsiconfd.check.common import Check, CheckResult, CheckStatus

# class AddonCheck(Check):
# 	def check(self) -> CheckResult:
# 		result = self.result
# 		failed_addons = _get_failed_addons()
# 		if failed_addons:
# 			result.check_status = CheckStatus.ERROR
# 			result.message = "Errors occurred while loading opsiconfd addons: "
# 			result.details["failed_addons"] = failed_addons
# 			for addon in failed_addons:
# 				result.message = result.message + f"{addon.get('name')} "

# 		return result

# docs = """
# ## Check Failed Addons

# Checks if there are any failed addons. If there are any failed addons, the check will return an error and list the failed addons.
# """

# failed_addons_check = AddonCheck(
# 	id="opsi_failed_addons",
# 	name="OPSI failed addons",
# 	description="Checks if there are any failed addons.",
# 	documentation=docs,
# 	status=CheckStatus.OK,
# 	message="No errors found while loading addons.",
# 	depot_check=False,
# )
