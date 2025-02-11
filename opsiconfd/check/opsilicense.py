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
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import config, opsi_config
from opsiconfd.utils.modules import module_available


@dataclass()
class OpsiLicensesLimitCheck(Check):
	id: str = "opsi_licenses:limit"
	name: str = "OPSI Licenses Limit"
	description: str = "Check opsi licensing limits"
	module_id: str = ""
	partial_check: bool = True

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"{self.id}:{self.module_id}"
		self.name = f"{self.name} {self.module_id!r}"
		self.description = f"{self.description} for module {self.module_id!r}"

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No licensing issues detected.",
			check_status=CheckStatus.OK,
		)
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
class OpsiLicensesMissingCustomCA(Check):
	id: str = "opsi_licenses:missing:custom_ca"
	name: str = "OPSI License missing for custom CA"
	description: str = "Check for missing custom CA license"
	partial_check: bool = True

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Module 'custom_ca' is not needed.",
			check_status=CheckStatus.OK,
		)
		if config.ssl_server_cert_type == "custom-ca":
			if module_available("custom_ca"):
				result.message = "ssl-server-cert-type is set to 'custom-ca' in configuration and Custom CA module is licensed."
			else:
				result.check_status = CheckStatus.ERROR
				result.message = "ssl-server-cert-type is set to 'custom-ca' in configuration but Custom CA module is not licensed."
		return result


@dataclass()
class OpsiLicensesMissingLetsEncrypt(Check):
	id: str = "opsi_licenses:missing:letsencrypt"
	name: str = "OPSI License missing for Let's Encrypt"
	description: str = "Check for missing Let's Encrypt license"
	partial_check: bool = True

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Module 'letsencrypt' is not needed.",
			check_status=CheckStatus.OK,
		)
		if config.ssl_server_cert_type == "letsencrypt":
			if module_available("letsencrypt"):
				result.message = "ssl-server-cert-type is set to 'letsencrypt' in configuration and Let's Encrypt module is licensed."
			else:
				result.check_status = CheckStatus.ERROR
				result.message = "ssl-server-cert-type is set to 'letsencrypt' in configuration but Let's Encrypt module is not licensed."
		return result


@dataclass()
class OpsiLicensesMissingSSO(Check):
	id: str = "opsi_licenses:missing:sso"
	name: str = "OPSI License missing for Single Sign-On"
	description: str = "Check for missing Single Sign-On license"
	partial_check: bool = True

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Module 'sso' is not needed.",
			check_status=CheckStatus.OK,
		)
		if config.saml_idp_entity_id:
			if module_available("sso"):
				result.message = "saml-idp-entity-id is set in configuration and Single Sign On module is licensed."
			else:
				result.check_status = CheckStatus.ERROR
				result.message = "saml-idp-entity-id is set in configuration but Single Sign On module is not licensed."
		return result


@dataclass()
class OpsiLicensesMissingScalability(Check):
	id: str = "opsi_licenses:missing:scalability1"
	name: str = "OPSI License missing for Scalability"
	description: str = "Check for missing Scalability license"
	partial_check: bool = True

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Module 'scalability1' is not needed.",
			check_status=CheckStatus.OK,
		)
		if config.workers > 1:
			if module_available("scalability1"):
				result.message = f"The number of workers is set to {config.workers} in configuration and Scalability module is licensed."
			else:
				result.check_status = CheckStatus.ERROR
				result.message = (
					f"The number of workers is set to {config.workers} in configuration but Scalability module is not licensed."
				)
		return result


@dataclass()
class OpsiLicensesMissingDirectoryConnector(Check):
	id: str = "opsi_licenses:missing:directory-connector"
	name: str = "OPSI License missing for Directory Connector"
	description: str = "Check for missing Directory Connector license"
	partial_check: bool = True

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Module 'directory-connector' is not needed.",
			check_status=CheckStatus.OK,
		)
		if opsi_config.get("ldap_auth", "ldap_url"):
			if module_available("directory-connector"):
				result.message = "ldap_auth is configured in opsi.conf and Directory Connector module is licensed."
			else:
				result.check_status = CheckStatus.ERROR
				result.message = "ldap_auth is configured in opsi.conf but Directory Connector module is not licensed."

		return result


@dataclass()
class OpsiLicensesCheck(Check):
	id: str = "opsi_licenses"
	name: str = "OPSI Licenses"
	description: str = "Check opsi licensing state"
	documentation: str = """
		## OPSI licenses

		Checks whether the imported licenses will soon exceed one of the defined limits (WARNING) or have already exceeded one (ERROR).
	"""

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No licensing issues detected.",
			check_status=CheckStatus.OK,
		)
		backend = get_unprotected_backend()
		licensing_info = backend.backend_getLicensingInfo()
		result.message = f"{licensing_info['client_numbers']['all']} active clients"
		result.details = {"client_numbers": licensing_info["client_numbers"]}
		self.add_partial_checks(OpsiLicensesMissingCustomCA())
		self.add_partial_checks(OpsiLicensesMissingLetsEncrypt())
		self.add_partial_checks(OpsiLicensesMissingSSO())
		self.add_partial_checks(OpsiLicensesMissingScalability())
		self.add_partial_checks(OpsiLicensesMissingDirectoryConnector())
		for module_id in licensing_info.get("modules", {}).keys():
			self.add_partial_checks(OpsiLicensesLimitCheck(module_id=module_id))
		return result


opsi_licenses_check = OpsiLicensesCheck()
check_manager.register(opsi_licenses_check)
