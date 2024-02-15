# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""
import grp
import os
import pwd
import subprocess
from pathlib import Path

from opsicommon.system.info import is_ucs

from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import is_local_user


def check_opsi_users() -> CheckResult:
	"""
	## Check users

	Checks if opsi depot user and opsiconfd user exist.
	If the system is bound to a domain, it checks if the users are domain users.
	Searches sssd, winbind, ldap in /etc/nsswitch.conf to determine the domain bind.
	"""
	result = CheckResult(
		check_id="opsi_users",
		check_name="OPSI Users ",
		check_description="Checks opsi users.",
		message="No Problems found with opsi users.",
		details={},
	)

	depot_user = opsi_config.get("depot_user", "username")
	opsiconfd_user = config.run_as_user

	for user in (depot_user, opsiconfd_user):
		try:
			partial_result = PartialCheckResult(
				check_id=f"opsi_user:exist:{user}",
				check_name=f"OPSI User exist {user}",
				check_status=CheckStatus.OK,
				message=(f"opsi user '{user}' does exist."),
				details={},
			)
			pwd.getpwnam(user)
		except KeyError:
			partial_result.message = f"opsi user '{user}' does not exist."
			partial_result.check_status = CheckStatus.ERROR

		result.add_partial_result(partial_result)

		if result.check_status != CheckStatus.OK:
			result.message = "A required user does not exist."
			return result

	domain_bind = None
	nsswitch_conf = Path("/etc/nsswitch.conf")
	if nsswitch_conf.exists():
		with nsswitch_conf.open() as nsswitch:
			if "sss" in nsswitch.read():
				domain_bind = "sss"
			if "winbind" in nsswitch.read():
				domain_bind = "winbind"
			if "ldap" in nsswitch.read():
				domain_bind = "ldap"
	if is_ucs():
		domain_bind = "ucs"

	logger.debug("Domain bind: %s", domain_bind)

	if not domain_bind:
		result.details = {"domain_bind": "No domain bind found."}
		return result

	for user in (depot_user, opsiconfd_user):
		partial_result = PartialCheckResult(
			check_id=f"opsi_users:domain:{user}",
			check_name=f"OPSI Users domain {user}",
			check_status=CheckStatus.OK,
			message=(f"opsi user '{user.pw_name} - id: {user.pw_uid}' is a domain user."),
			details={},
		)

		local_user = is_local_user(user)
		domain_user = False

		user = pwd.getpwnam(user)
		user_groups = [grp.getgrgid(g).gr_name for g in os.getgrouplist(user.pw_name, user.pw_gid)]

		# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#domain-users
		if "domain users" in user_groups:
			domain_user = True

		if domain_bind == "ucs":
			try:
				univention_ldapsearch = subprocess.run(
					["univention-ldapsearch", "-LLL", f"uid={user.pw_name}"],
					check=True,
					capture_output=True,
				).stdout.decode("utf-8")
			except subprocess.CalledProcessError as e:
				logger.error("Failed to run univention-ldapsearch: %s", e)
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = "Failed to run univention-ldapsearch"
				partial_result.details = {"error": str(e)}
			if f"dn: uid={user.pw_name}" in univention_ldapsearch:
				domain_user = True

		if local_user and not domain_user:
			partial_result.check_status = CheckStatus.WARNING
			partial_result.message = (
				f"{domain_bind} found in /etc/nsswitch.conf, but opsi user '{user.pw_name} - id: {user.pw_uid}' is a local system user. "
				"Please check if this is intended."
			)
			partial_result.details = {
				"domain_bind": domain_bind,
				"groups": user_groups,
				"user": user.pw_name,
				"uid": user.pw_uid,
				"gid": user.pw_gid,
				"home": user.pw_dir,
				"shell": user.pw_shell,
				"comment": user.pw_gecos,
			}
		elif not local_user and domain_user:
			partial_result.check_status = CheckStatus.OK
			partial_result.message = f"opsi user '{user.pw_name} - id: {user.pw_uid}' is a domain user."
		else:
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"opsi user '{user.pw_name} - id: {user.pw_uid}' is a local system user and a domain user."

		result.add_partial_result(partial_result)

	if result.check_status != CheckStatus.OK:
		result.message = "Problems found with opsi users. Please check the details."
	return result
