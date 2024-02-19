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
from opsiconfd.utils import PASSWD_DOMAIN_SERVICES, get_passwd_services, get_user_passwd_details


def check_opsi_users() -> CheckResult:
	"""
	## Check users

	Checks if opsi depot user and opsiconfd user exist.
	If the system is part of a domain, it checks if the users are domain users.
	Searches sssd, winbind, ldap in /etc/nsswitch.conf to determine the domain bind.
	"""
	result = CheckResult(
		check_id="opsi_users",
		check_name="OPSI Users ",
		check_description="Checks opsi users.",
		message="No problems found with opsi users.",
		details={},
	)

	depot_user = opsi_config.get("depot_user", "username")
	opsiconfd_user = config.run_as_user

	for user in (depot_user, opsiconfd_user):
		partial_result = PartialCheckResult(
			check_id=f"opsi_user:exist:{user}",
			check_name=f"OPSI User exist {user}",
			check_status=CheckStatus.OK,
			message=(f"opsi user '{user}' does exist."),
			details={},
		)
		try:
			pwd.getpwnam(user)
		except KeyError:
			partial_result.message = f"opsi user '{user}' does not exist."
			partial_result.check_status = CheckStatus.ERROR

		result.add_partial_result(partial_result)

	if result.check_status != CheckStatus.OK:
		result.message = "A required user does not exist."
		return result

	for user in (depot_user, opsiconfd_user):
		user_details = get_user_passwd_details(user)
		partial_result = PartialCheckResult(
			check_id=f"opsi_user:uid:{user}",
			check_name=f"OPSI User UID {user}",
			check_status=CheckStatus.OK,
			message=(f"Only one passwd entry for opsi user '{user}' found."),
			details={"passwd_info": user_details.passwd_info},
		)

		uid = 0
		for info in user_details.passwd_info.values():
			if uid != 0 and uid == info.uid:
				partial_result.check_status = CheckStatus.WARNING
				partial_result.message = f"opsi user '{user}' found multiple times with the same ID: {uid} == {info.uid}"
				break
			elif uid != 0 and uid != info.uid:
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"opsi user '{user}' with different UIDs found: {uid} != {info.uid}"
				break
			uid = info.uid

		if partial_result.check_status != CheckStatus.OK:
			result.add_partial_result(partial_result)
			break

		passwd_services = get_passwd_services()
		logger.debug("passwd_services: %s", passwd_services)

		if (
			any(service in PASSWD_DOMAIN_SERVICES for service in passwd_services)
			and not user_details.domain_services
			and user_details.local_services
		):
			partial_result.check_status = CheckStatus.WARNING
			for service in user_details.local_services:
				partial_result.message = (
					f"opsi user '{user} - id: {user_details.passwd_info[service].uid}' is a local system user (service: '{service}'), "
					f"but found domain service in /etc/nsswitch.conf (passwd services: {passwd_services}). "
					"Please check if this is intended."
				)

		result.add_partial_result(partial_result)
	if result.check_status != CheckStatus.OK:
		result.message = "Possible issues with opsi users. Please check the details."
		return result
	return result


def get_domain_bind() -> str:
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
