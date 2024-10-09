# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """


from dataclasses import dataclass

import ldap3  # type: ignore[import]

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import ldap3_uri_to_str


@dataclass()
class LdapConnectionCheck(Check):
	id: str = "ldap_connection"
	name: str = "LDAP Connection"
	description: str = "Checks whether opsi can connect to the configured LDAP server."
	depot_check: bool = False
	documentation: str = """
		## Check LDAP Connection

		Checks whether opsi can connect to the configured LDAP server.
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="LDAP authentication is not configured.",
			check_status=CheckStatus.OK,
		)
		ldap_conf = opsi_config.get("ldap_auth")
		if ldap_conf["ldap_url"]:
			logger.debug("Using LDAP auth with config: %s", ldap_conf)
			if "directory-connector" in get_unprotected_backend().available_modules:
				ldap_connection = None
				try:
					result.message = "The connection to the LDAP server does work."
					server = ldap3.Server(ldap3_uri_to_str(ldap3.utils.uri.parse_uri(ldap_conf["ldap_url"])))  # type: ignore[no-untyped-call]
					ldap_connection = ldap3.Connection(server)
					ldap_connection.bind()
				except ldap3.core.exceptions.LDAPException as error:
					logger.debug("Could not connect to LDAP Server: %s", error)
					result.check_status = CheckStatus.ERROR
					result.message = "Could not connect to LDAP Server."
					result.details["error"] = str(error)
				finally:
					if ldap_connection:
						ldap_connection.unbind()
			else:
				result.check_status = CheckStatus.ERROR
				result.message = "LDAP authentication is configured, but the Directory Connector module is not licensed."
		return result


ldap_connection_check = LdapConnectionCheck()
check_manager.register(ldap_connection_check)
