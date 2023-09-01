# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.auth.pam
"""

from __future__ import annotations

import os
import pwd
from grp import getgrgid
from os import getgrouplist

import pam  # type: ignore[import]
from opsicommon.exceptions import BackendAuthenticationError  # type: ignore[import]
from opsicommon.system.info import linux_distro_id_like_contains  # type: ignore[import]

from ..logging import logger
from . import AuthenticationModule


class PAMAuthentication(AuthenticationModule):
	def __init__(self, pam_service: str | None = None):
		super().__init__()
		self._pam_service = pam_service
		if not self._pam_service:
			if os.path.exists("/etc/pam.d/opsi-auth"):
				# Prefering our own - if present.
				self._pam_service = "opsi-auth"
			elif linux_distro_id_like_contains(("sles", "opensuse")):
				self._pam_service = "sshd"
			elif linux_distro_id_like_contains(("rhel", "centos", "fedora")):
				self._pam_service = "system-auth"
			else:
				self._pam_service = "common-auth"

	def get_instance(self) -> PAMAuthentication:
		return PAMAuthentication(self._pam_service)

	def authenticate(self, username: str, password: str) -> None:
		"""
		Authenticate a user by PAM (Pluggable Authentication Modules).
		Important: the uid running this code needs access to /etc/shadow
		if os uses traditional unix authentication mechanisms.

		:param service: The PAM service to use. Leave None for autodetection.
		:type service: str
		:raises BackendAuthenticationError: If authentication fails.
		"""
		logger.confidential("Trying to authenticate user %s with password %s by PAM", username, password)
		logger.trace("Attempting PAM authentication as user %s (service=%s)...", username, self._pam_service)

		try:
			auth = pam.pam()
			if not auth.authenticate(username, password, service=self._pam_service):
				logger.trace("PAM authentication failed: %s (code %s)", auth.reason, auth.code)
				raise RuntimeError(auth.reason)

			logger.trace("PAM authentication successful.")
		except Exception as err:
			raise BackendAuthenticationError(f"PAM authentication failed for user '{username}': {err}") from err

	def get_groupnames(self, username: str) -> set[str]:
		"""
		Read the groups of a user.

		:returns: Group the user is a member of.
		:rtype: set()
		"""
		logger.debug("Getting groups of user %s", username)
		primary_gid = pwd.getpwnam(username).pw_gid
		logger.debug("Primary group id of user %s is %s", username, primary_gid)
		groups = set()
		for gid in getgrouplist(username, primary_gid):
			try:
				groups.add(getgrgid(gid).gr_name)
			except KeyError as err:
				logger.warning(err)
		logger.debug("User %s is member of groups: %s", username, groups)
		return {g.lower() for g in groups}
