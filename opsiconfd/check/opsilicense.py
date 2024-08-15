# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from __future__ import annotations

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult, exc_to_result, Check, CheckRegistry

def check_opsi_licenses(result: CheckResult) -> CheckResult:
	"""
	## OPSI licenses

	Checks whether the imported licenses will soon exceed one of the defined limits (WARNING) or have already exceeded one (ERROR).
	"""
	result = CheckResult(check_id="opsi_licenses", check_name="OPSI licenses", check_description="Check opsi licensing state")
	with exc_to_result(result):
		backend = get_unprotected_backend()
		licensing_info = backend.backend_getLicensingInfo()
		result.message = f"{licensing_info['client_numbers']['all']} active clients"
		result.details = {"client_numbers": licensing_info["client_numbers"]}
		for module_id, module_data in licensing_info.get("modules", {}).items():
			if module_data["state"] == "free":
				continue

			partial_result = PartialCheckResult(
				check_id=f"opsi_licenses:{module_id}",
				check_name=f"OPSI license for module {module_id!r}",
				details={"module_id": module_id, "state": module_data["state"], "client_number": module_data["client_number"]},
			)
			if module_data["state"] == "close_to_limit":
				partial_result.check_status = CheckStatus.WARNING
				partial_result.message = f"License for module '{module_id}' is close to the limit of {module_data['client_number']}."
			elif module_data["state"] == "over_limit":
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"License for module '{module_id}' is over the limit of {module_data['client_number']}."
			else:
				partial_result.check_status = CheckStatus.OK
				partial_result.message = f"License for module '{module_id}' is below the limit of {module_data['client_number']}."
			result.add_partial_result(partial_result)

		if result.check_status == CheckStatus.OK:
			result.message += ", no licensing issues."
		else:
			result.message += ", licensing issues detected."
	return result

docs = """
## OPSI licenses

Checks whether the imported licenses will soon exceed one of the defined limits (WARNING) or have already exceeded one (ERROR).
"""

opsi_licenses_check = Check(
	id="opsi_licenses",
	name="OPSI licenses",
	description="Check opsi licensing state",
	documentation=docs,
	depot_check=False,
	message="No licensing issues detected.",
	check_function=check_opsi_licenses
)
CheckRegistry().register(opsi_licenses_check)