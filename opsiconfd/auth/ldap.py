# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.auth.ldap
"""

from __future__ import annotations

from typing import Literal

import ldap3
from ldap3.core.exceptions import LDAPObjectClassError
from ldap3.utils.uri import parse_uri
from opsicommon.exceptions import BackendAuthenticationError

from opsiconfd.utils import ldap3_uri_to_str

from ..logging import logger
from . import AuthenticationMethod, AuthenticationModule


class LDAPAuthentication(AuthenticationModule):
	authentication_method = AuthenticationMethod.PASSWORD_LDAP

	def __init__(
		self, ldap_url: str, bind_user: str | None = None, group_filter: str | None = None, use_member_of_rdn: bool = False
	) -> None:
		"""
		Authentication module using LDAP.

		This can be used to authenticate users against OpenLDAP
		or an Active Directory server.

		:param ldap_url: The LDAP connection url.
		:param bind_user: (optional) The simple bind is performed with this user.
		        The ``bind_user`` has to contain the placeholder ``{username}`` which will be
		        replaced by the username auth authenticating user.
		        The placeholder ``{base}`` will be replaced by the base dn.
		        For active directory ``{username}@your.realm`` should work.
		        For OpenLDAP a DN like ``uid={username},ou=Users,{base}`` should be used.
		        If ommitted the bind_user will be guessed.
		:param group_filter: (optional) The filter which is used when searching groups.
		:param use_member_of_rdn: (optional) If set to ``True`` the RDN of the
		        `memberOf`` attribute will be used to get the group name, without searching the group.
		Examples::
		        >>> active_directory_auth = LDAPAuthentication("ldaps://ad.company.de/dc=company,dc=de", "{username}@company.de")
		        >>> open_ldap_auth = LDAPAuthentication("ldap://ldap.company.de/dc=company,dc=de", "uid={username},dc=Users,{base}")
		"""
		super().__init__()
		self._ldap_url = ldap_url
		self._uri = parse_uri(self._ldap_url)  # type: ignore[no-untyped-call]
		self._group_filter = group_filter
		self._use_member_of_rdn = use_member_of_rdn
		self._ldap: ldap3.Connection | None = None
		if not bind_user:
			if self._uri["base"]:
				realm = ".".join([dc.split("=")[1] for dc in self._uri["base"].split(",")])
			else:
				realm = self._uri["host"]
			bind_user = "{username}@" + realm
		self._bind_user = bind_user
		logger.info(
			"LDAP auth configuration: server_url=%s, base=%s, bind_user=%s, group_filter=%s, use_member_of_rdn=%s",
			self.server_url,
			self._uri["base"],
			self._bind_user,
			self._group_filter,
			self._use_member_of_rdn,
		)

	@property
	def server_url(self) -> str:
		return ldap3_uri_to_str(self._uri)

	def get_instance(self) -> LDAPAuthentication:
		return LDAPAuthentication(self._ldap_url, self._bind_user, self._group_filter)

	def authenticate(self, username: str, password: str) -> None:
		"""
		Authenticate a user by LDAP bind

		:raises BackendAuthenticationError: If authentication fails.
		"""
		self._ldap = None
		try:
			if "{base}" in self._bind_user and not self._uri["base"]:
				raise RuntimeError(
					f"Placeholder for base DN in bind user '{self._bind_user}', but no base DN in LDAP URL '{self._ldap_url}'"
				)
			bind_user = self._bind_user.replace("{username}", username).replace("{base}", self._uri["base"])
			logger.info("Binding as user '%s' to server '%s'", bind_user, self.server_url)
			# self._ldap = ldap3.Connection(server=self.server_url, client_strategy=ldap3.SAFE_SYNC, user=bind_user, password=password)
			self._ldap = ldap3.Connection(server=self.server_url, user=bind_user, password=password)
			if not self._ldap.bind():
				raise RuntimeError(f"bind failed: {self._ldap.result}")
			# self._ldap.extend.standard.who_am_i()
		except Exception as err:
			logger.info("LDAP authentication failed for user '%s'", username, exc_info=True)
			raise BackendAuthenticationError(f"LDAP authentication failed for user '{username}': {err}") from err

	def get_groupnames(self, username: str) -> set[str]:
		groupnames = set()
		if not self._ldap:
			raise RuntimeError("Failed to get groupnames, not connected to LDAP")

		ldap_type = "openldap"
		user_dn = None
		group_dns = []
		for user_filter in [f"(&(objectclass=user)(sAMAccountName={username}))", f"(&(objectclass=posixAccount)(uid={username}))"]:
			try:
				logger.debug("Searching user in LDAP base=%s, filter=%s", self._uri["base"], user_filter)
				self._ldap.search(
					self._uri["base"],
					user_filter,
					search_scope=ldap3.SUBTREE,
					attributes="*",
				)
				for entry in sorted(self._ldap.entries):
					logger.trace("Found user: %s", entry)
					user_dn = entry.entry_dn
					if "sAMAccountName" in entry.entry_attributes:
						ldap_type = "ad"
						groupnames.add("domain users")
					if "memberOf" in entry.entry_attributes:
						group_dns.extend(entry.memberOf)
						if self._use_member_of_rdn:
							groupnames.update([g.split(",")[0].split("=", 1)[1] for g in entry.memberOf])
				if user_dn:
					break
			except LDAPObjectClassError as err:
				logger.debug(err)
			if user_dn and ldap_type == "ad":
				break

		if not user_dn:
			raise RuntimeError(f"User '{username}' not found in LDAP ({ldap_type})")

		logger.info("User %s found in LDAP (%s): %s", username, ldap_type, user_dn)
		logger.debug("User '%s' groups: %s", user_dn, group_dns)

		if ldap_type == "ad" and not group_dns:
			logger.debug("User '%s' has no groups in LDAP (%s)", username, ldap_type)
			return {g.lower() for g in groupnames}

		if self._use_member_of_rdn:
			logger.debug("Returning groups by memberOf RDN")
			return {g.lower() for g in groupnames}

		group_filter = self._group_filter or ""
		attributes = []
		if ldap_type == "ad":
			if self._group_filter is None:
				group_filter = "(objectclass=group)"
			attributes = ["sAMAccountName", "member", "memberOf"]
		else:
			if self._group_filter is None:
				group_filter = "(objectclass=posixGroup)"
			attributes = ["cn", "member", "memberUid"]

		scope: Literal["BASE", "LEVEL", "SUBTREE"] = ldap3.BASE if group_dns else ldap3.SUBTREE
		for base in group_dns or [self._uri["base"]]:
			logger.debug("Searching groups in LDAP base=%s, scope=%s, filter=%s", base, scope, group_filter)
			self._ldap.search(base, group_filter, search_scope=scope, attributes=attributes)

			for entry in sorted(self._ldap.entries):
				logger.trace("Found group: %s", entry)
				group_name = None
				if "sAMAccountName" in entry.entry_attributes:
					group_name = str(entry.sAMAccountName)
				else:
					group_name = str(entry.cn)

				if group_dns:
					logger.debug("Entry %s by memberOf", entry.entry_dn)
					groupnames.add(group_name)
					# Get nested groups (one level only, uses RDN)
					if "memberOf" in entry.entry_attributes:
						logger.debug("Nested groups of %s: %s", entry.entry_dn, entry.memberOf)
						for nested_group_dn in entry.memberOf:
							groupnames.add(nested_group_dn.split(",")[0].split("=", 1)[1])

				else:
					if "member" in entry.entry_attributes:
						logger.debug("Entry %s member: %s", entry.entry_dn, entry.member)
						for member in entry.member:
							if user_dn.lower() == member.lower():
								groupnames.add(group_name)
								break
					if "memberUid" in entry.entry_attributes:
						logger.debug("Entry %s memberUid: %s", entry.entry_dn, entry.memberUid)
						for member in entry.memberUid:
							if member.lower() == username.lower():
								groupnames.add(group_name)
								break

		return {g.lower() for g in groupnames}

	def __del__(self) -> None:
		if self._ldap:
			try:
				self._ldap.unbind()
			except Exception as err:
				logger.warning(err)
