# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """


from dataclasses import dataclass

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager, exc_to_result


@dataclass()
class OpsiLicensesLimitCheck(Check):
	id: str = "opsi_licenses:limit"
	name: str = "OPSI licenses limit"
	description: str = "Check opsi licensing limits"
	module_id: str = ""
	partial_check: bool = True
	depot_check: bool = False

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"{self.id}:{self.module_id}"
		self.name = f"{self.name} {self.module_id!r}"
		self.description = f"{self.description} for module {self.module_id!r}"

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No licensing issues detected.",
			check_status=CheckStatus.OK,
		)
		with exc_to_result(result):
			backend = get_unprotected_backend()
			licensing_info = backend.backend_getLicensingInfo()
			module_data = licensing_info.get("modules", {}).get(self.module_id)
			if not module_data:
				result.message = f"Module {self.module_id!r} not found."
				return result

			if module_data["state"] == "free":
				result.message = f"License for module '{self.module_id}' is free."
				return result

			if module_data["state"] == "close_to_limit":
				result.check_status = CheckStatus.WARNING
				result.message = f"License for module '{self.module_id}' is close to the limit of {module_data['client_number']}."
			elif module_data["state"] == "over_limit":
				result.check_status = CheckStatus.ERROR
				result.message = f"License for module '{self.module_id}' is over the limit of {module_data['client_number']}."
			else:
				result.check_status = CheckStatus.OK
				result.message = f"License for module '{self.module_id}' is below the limit of {module_data['client_number']}."

		return result


@dataclass()
class OpsiLicensesCheck(Check):
	id: str = "opsi_licenses"
	name: str = "OPSI licenses"
	description: str = "Check opsi licensing state"
	depot_check: bool = False
	documentation: str = """
		## OPSI licenses

		Checks whether the imported licenses will soon exceed one of the defined limits (WARNING) or have already exceeded one (ERROR).
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No licensing issues detected.",
			check_status=CheckStatus.OK,
		)
		with exc_to_result(result):
			backend = get_unprotected_backend()
			licensing_info = backend.backend_getLicensingInfo()
			result.message = f"{licensing_info['client_numbers']['all']} active clients"
			result.details = {"client_numbers": licensing_info["client_numbers"]}
			for module_id in licensing_info.get("modules", {}).keys():
				self.add_partial_checks(OpsiLicensesLimitCheck(module_id=module_id))

		return result


opsi_licenses_check = OpsiLicensesCheck()
check_manager.register(opsi_licenses_check)
