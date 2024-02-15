# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check users
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

	domain_bind = get_domain_bind()

	logger.debug("Domain bind: %s", domain_bind)

	if not domain_bind:
		result.details = {"domain_bind": "No domain bind found."}
		return result

	for user in (depot_user, opsiconfd_user):
		user = pwd.getpwnam(user)

		partial_result = PartialCheckResult(
			check_id=f"opsi_users:domain:{user}",
			check_name=f"OPSI Users domain {user}",
			check_status=CheckStatus.OK,
			message=(f"opsi user '{user.pw_name} - id: {user.pw_uid}' is a domain user."),
			details={},
		)

		local_user = is_local_user(user.pw_name)
		domain_user = is_domain_user(user.pw_name)

		if local_user and not domain_user:
			partial_result.check_status = CheckStatus.WARNING
			partial_result.message = (
				f"{domain_bind} found in /etc/nsswitch.conf, but opsi user '{user.pw_name} - id: {user.pw_uid}' is a local system user. "
				"Please check if this is intended."
			)
			partial_result.details = {"domain_bind": domain_bind, "user": user.pw_name, "uid": user.pw_uid, "gid": user.pw_gid}
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


def get_domain_bind() -> str:
	"""
	Returns the domain bind found in /etc/nsswitch.conf
	"""
	if is_ucs():
		return "ucs"

	nsswitch_conf = Path("/etc/nsswitch.conf")
	if not nsswitch_conf.is_file():
		return ""

	with open(nsswitch_conf, "r", encoding="utf-8") as handle:
		for line in handle:
			if "sss" in line:
				return "sss"
			if "winbind" in line:
				return "winbind"
			if "ldap" in line:
				return "ldap"

	return ""


def is_domain_user(username: str) -> bool:
	"""
	Returns True if the user is a domain user
	"""
	try:
		user = pwd.getpwnam(username)
	except KeyError:
		return False

	user_groups = [grp.getgrgid(g).gr_name for g in os.getgrouplist(user.pw_name, user.pw_gid)]

	# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#domain-users
	if "domain users" in user_groups:
		return True

	if is_ucs():
		try:
			univention_ldapsearch = subprocess.run(
				["univention-ldapsearch", "-LLL", f"uid={user.pw_name}"],
				check=True,
				capture_output=True,
			).stdout.decode("utf-8")
		except subprocess.CalledProcessError as err:
			logger.error("Failed to run univention-ldapsearch: %s", err)
			return False

		if f"dn: uid={user.pw_name}" in univention_ldapsearch:
			return True

	return False
