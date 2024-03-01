# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.auth
"""

from __future__ import annotations

from enum import StrEnum
from opsicommon.exceptions import BackendAuthenticationError

from ..config import opsi_config

class AuthenticationMethod(StrEnum):
	ADMIN_NETWORKS = "admin_networks"
	HARDWARE_ADDRESS = "hardware_address"
	HOST_ID = "host_id"
	HOST_KEY = "host_key"
	NOT_SET = "not_set"
	PASSWORD_FILE = "password_file"
	PASSWORD_LDAP = "password_ldap"
	PASSWORD_ONETIME = "password_onetime"
	PASSWORD_PAM = "password_pam"
	SYSTEM_UUID = "system_uuid"
	TLS_CERTIFICATE = "tls_certificate"
	TOTP = "totp"
	USERNAME = "username"


class AuthenticationModule:
	authentication_method = AuthenticationMethod.NOT_SET

	def get_instance(self) -> AuthenticationModule:
		return self.__class__()

	def authenticate(self, username: str, password: str) -> None:
		raise BackendAuthenticationError("Not implemented")

	def get_groupnames(self, username: str) -> set[str]:
		return set()

	def get_admin_groupname(self) -> str:
		return opsi_config.get("groups", "admingroup").lower()

	def get_read_only_groupnames(self) -> set[str]:
		readonly_group = opsi_config.get("groups", "readonly").lower()
		if readonly_group:
			return {readonly_group}
		return set()

	def user_is_admin(self, username: str) -> bool:
		return self.get_admin_groupname() in self.get_groupnames(username)

	def user_is_read_only(self, username: str, forced_user_groupnames: set[str] | None = None) -> bool:
		user_groupnames = set()
		if forced_user_groupnames is None:
			user_groupnames = self.get_groupnames(username)
		else:
			user_groupnames = forced_user_groupnames

		read_only_groupnames = self.get_read_only_groupnames()
		for group_name in user_groupnames:
			if group_name in read_only_groupnames:
				return True
		return False
