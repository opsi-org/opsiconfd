# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check users
"""
import pwd

from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import NameService, get_passwd_services, get_user_passwd_details


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
			details={"user_info": user_details},
		)

		uid = 0
		for user_info in user_details:
			if uid != 0 and uid == user_info.uid:
				partial_result.check_status = CheckStatus.WARNING
				partial_result.message = f"opsi user '{user}' found multiple times with the same ID: {uid} == {user_info.uid}"
				break
			elif uid != 0 and uid != user_info.uid:
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"opsi user '{user}' with different UIDs found: {uid} != {user_info.uid}"
				break
			uid = user_info.uid

		if partial_result.check_status != CheckStatus.OK:
			result.add_partial_result(partial_result)
			break

		passwd_services = get_passwd_services()
		logger.debug("passwd_services: %s", passwd_services)

		local_infos = [user_info for user_info in user_details if NameService(user_info.service).is_local]
		if (
			any(not NameService(service).is_local for service in passwd_services)
			and not [user_info for user_info in user_details if not NameService(user_info.service).is_local]
			and local_infos
		):
			partial_result.check_status = CheckStatus.WARNING
			for info in local_infos:
				partial_result.message = (
					f"opsi user '{user} - id: {info.uid}' is a local system user (service: '{info.service}'), "
					f"but found domain service in /etc/nsswitch.conf (passwd services: {[str(passwd_service) for passwd_service in passwd_services]}). "
					"Please check if this is intended."
				)

		result.add_partial_result(partial_result)
	if result.check_status != CheckStatus.OK:
		result.message = "Possible issues with opsi users. Please check the details."
		return result
	return result
