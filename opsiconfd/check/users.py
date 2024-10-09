# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check users
# """

from dataclasses import dataclass

from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import get_passwd_services, get_user_passwd_details, user_exists


@dataclass()
class OpsiUserExistCheck(Check):
	id: str = "opsi_user:exits"
	name: str = "OPSI User Exists"
	description: str = "Check if opsi user exists."
	partial_check: bool = True
	user: str = ""

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"opsi_user:exist:{self.user}"
		self.name = f"OPSI User Exists: {self.user}"
		self.description = f"Check if opsi user '{self.user}' exists."

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message=f"OPSI user '{self.user}' does exist.",
			check_status=CheckStatus.OK,
		)

		if not user_exists(self.user):
			result.message = f"OPSI user '{self.user}' does not exist."
			result.check_status = CheckStatus.ERROR

		return result


@dataclass()
class OpsiUserUIDCheck(Check):
	id: str = "opsi_user:uid"
	name: str = "OPSI User UID"
	description: str = "Check if opsi user UID is unique."
	partial_check: bool = True
	user: str = ""

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"opsi_user:uid:{self.user}"
		self.name = f"OPSI User UID: {self.user}"
		self.description = f"Check if opsi user '{self.user}' UID is unique."

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message=f"Only one passwd entry for opsi user '{self.user}' found.",
			check_status=CheckStatus.OK,
		)

		user_details = get_user_passwd_details(self.user)
		uid = 0
		for user_info in user_details:
			if uid != 0 and uid == user_info.uid:
				result.check_status = CheckStatus.WARNING
				result.message = f"opsi user '{self.user}' found multiple times with the same ID: {uid} == {user_info.uid}"
				break
			elif uid != 0 and uid != user_info.uid:
				result.check_status = CheckStatus.ERROR
				result.message = f"opsi user '{self.user}' with different UIDs found: {uid} != {user_info.uid}"
				break
			uid = user_info.uid

		if result.check_status != CheckStatus.OK:
			return result

		passwd_services = get_passwd_services()
		logger.debug("passwd_services: %s ", passwd_services)

		local_infos = [user_info for user_info in user_details if user_info.service.is_local]
		non_local_infos = [user_info for user_info in user_details if not user_info.service.is_local]
		if any(not service.is_local for service in passwd_services) and local_infos and not non_local_infos:
			# User is only local, but a non local service was found in /etc/nsswitch.conf
			result.check_status = CheckStatus.WARNING
			result.message = (
				f"opsi user '{self.user}' (uid: {local_infos[0].uid}) is a local system user (service: '{local_infos[0].service}'), "
				f"but found a domain service in /etc/nsswitch.conf (passwd services: {[str(s) for s in passwd_services]}). "
				"Please check if this is intended."
			)
		return result


@dataclass()
class OpsiUsersCheck(Check):
	id: str = "opsi_users"
	name: str = "OPSI Users"
	description: str = "Check opsi users."
	documentation: str = """
		## Check users

		Checks if opsi depot user and opsiconfd user exist.
		If the system is part of a domain, it checks if the users are domain users.
		Searches sssd, winbind, ldap in /etc/nsswitch.conf to determine the domain bind.
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No problems found with opsi users.",
			check_status=CheckStatus.OK,
		)

		depot_user = opsi_config.get("depot_user", "username")
		opsiconfd_user = config.run_as_user
		for user in (depot_user, opsiconfd_user):
			self.add_partial_checks(OpsiUserExistCheck(user=user))
			self.add_partial_checks(OpsiUserUIDCheck(user=user))

		return result


opsi_users_check = OpsiUsersCheck()
check_manager.register(opsi_users_check)
