# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""
from pathlib import Path

import ldap3  # type: ignore[import]

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import CheckResult, CheckStatus
from opsiconfd.config import opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import ldap3_uri_to_str


def check_ldap_connection() -> CheckResult:
	"""
	## Check LDAP Connection

	Checks whether opsi can connect to the configured LDAP server.
	"""
	result = CheckResult(
		check_id="opsi_ldap_connection",
		check_name="OPSI LDAP Connection",
		check_description="Checks whether opsi can connect to the configured LDAP server.",
		message="LDAP authentication is not configured.",
		details={},
	)
	ldap_conf = opsi_config.get("ldap_auth")
	if ldap_conf["ldap_url"]:
		logger.debug("Using LDAP auth with config: %s", ldap_conf)
		if "directory-connector" in get_unprotected_backend().available_modules:
			ldap_connection = None
			try:
				result.message = "The connection to the LDAP server does work."
				server = ldap3.Server(ldap3_uri_to_str(ldap3.utils.uri.parse_uri(ldap_conf["ldap_url"])))
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


def check_opsi_depot_user() -> CheckResult:
	"""
	## Check Depot user

	Checks if depot user is local system user.
	"""
	result = CheckResult(
		check_id="opsi_depot_user",
		check_name="OPSI Depot User",
		check_description="Check if depot user is local system user.",
		message="opsi depot user is a local system user. LDAP authentication not is configured.",
		check_status=CheckStatus.OK,
		details={},
	)
	ldap_conf = opsi_config.get("ldap_auth")

	with Path("/etc/passwd").open() as passwd:
		if opsi_config.get("depot_user", "username") not in passwd.read():
			if ldap_conf["ldap_url"]:
				result.message = "LDAP authentication is configured and opsi depot user is a domain user."
				result.check_status = CheckStatus.OK
			else:
				result.message = "LDAP authentication not is configured and opsi depot user is not a local system user."
				result.check_status = CheckStatus.ERROR
		else:
			if ldap_conf["ldap_url"]:
				result.message = "LDAP authentication is configured. But opsi depot user is a local system user."
				result.check_status = CheckStatus.ERROR

	return result
