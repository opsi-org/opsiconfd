# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.auth
"""

from __future__ import annotations

from opsicommon.exceptions import BackendAuthenticationError

from .const import AuthenticationMethod


class AuthenticationModule:
	authentication_method = AuthenticationMethod.NOT_SET

	def get_instance(self) -> AuthenticationModule:
		return self.__class__()

	def authenticate(self, username: str, password: str) -> None:
		raise BackendAuthenticationError("Not implemented")

	def get_groupnames(self, username: str) -> set[str]:
		return set()
