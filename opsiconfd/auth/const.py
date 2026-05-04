# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.auth
"""

from __future__ import annotations

from enum import StrEnum


class AuthenticationMethod(StrEnum):
	ADMIN_NETWORKS = "admin_networks"
	HARDWARE_ADDRESS = "hardware_address"
	HOST_ID = "host_id"
	HOST_KEY = "host_key"
	NOT_SET = "not_set"
	SAML = "saml"
	PASSWORD_DATABASE = "password_database"
	PASSWORD_LDAP = "password_ldap"
	PASSWORD_ONETIME = "password_onetime"
	PASSWORD_PAM = "password_pam"
	SYSTEM_UUID = "system_uuid"
	TLS_CERTIFICATE = "tls_certificate"
	TOKEN_DATABASE = "token_database"
	TOTP = "totp"
	USERNAME = "username"
