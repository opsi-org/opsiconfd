# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from opsi.system.info import is_ucs

from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import DEPOT_DIR, config, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import get_passwd_services, get_user_passwd_details, user_exists


@dataclass()
class OpsiUserCheck(Check):
	id: str = "opsi_user"
	name: str = "OPSI User"
	description: str = "Check OPSI user."
	depot_check: bool = True
	user: str = ""
	login_allowed: bool = False
	must_own_home: bool = True

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"opsi_user:{self.user}"
		self.name = f"OPSI User: {self.user}"
		self.description = f"Check OPSI user '{self.user}'."

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message=f"OPSI user '{self.user}' does exist and is configured correctly.",
			check_status=CheckStatus.OK,
		)

		if not user_exists(self.user):
			result.message = f"OPSI user '{self.user}' does not exist."
			result.check_status = CheckStatus.ERROR
			return result

		user_details = get_user_passwd_details(self.user)
		uid = -1
		for user_info in user_details:
			if uid != -1 and uid == user_info.uid:
				result.check_status = CheckStatus.WARNING
				result.message = f"OPSI user '{self.user}' found multiple times with the same ID: {uid} == {user_info.uid}"
				break
			elif uid != -1 and uid != user_info.uid:
				result.check_status = CheckStatus.ERROR
				result.message = f"OPSI user '{self.user}' with different UIDs found: {uid} != {user_info.uid}"
				break
			result.details = {k: str(v) if isinstance(v, Path) else v for k, v in asdict(user_info).items()}
			uid = user_info.uid
			if not self.login_allowed and str(user_info.shell) not in ("/bin/false", "/sbin/nologin", "/usr/sbin/nologin"):
				result.check_status = CheckStatus.WARNING
				result.message = f"OPSI user '{self.user}' has a login shell configured: {user_info.shell}"

			if user_info.home.exists():
				stat = user_info.home.stat()
				if self.must_own_home and stat.st_uid != user_info.uid:
					result.check_status = CheckStatus.ERROR
					result.message = (
						f"OPSI user '{self.user}' has a home directory '{user_info.home}' "
						f"not owned by the user (uid: {stat.st_uid} != {user_info.uid})"
					)
				if os.geteuid() == user_info.uid:
					if not os.access(user_info.home, os.R_OK | os.W_OK | os.X_OK):
						result.check_status = CheckStatus.ERROR
						result.message = f"OPSI user '{self.user}' cannot access its home directory: '{user_info.home}'"
			else:
				result.check_status = CheckStatus.ERROR
				result.message = f"OPSI user '{self.user}' has a non existing home directory configured: '{user_info.home}'"

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
				f"OPSI user '{self.user}' (uid: {local_infos[0].uid}) is a local system user (service: '{local_infos[0].service}'), "
				f"but found a domain service in /etc/nsswitch.conf (passwd services: {[str(s) for s in passwd_services]}). "
				"Please check if this is intended."
			)

		depot_dir = Path(DEPOT_DIR)
		if os.geteuid() == uid and depot_dir.exists():
			if not os.access(depot_dir, os.R_OK | os.W_OK | os.X_OK):
				result.check_status = CheckStatus.ERROR
				result.message = f"OPSI user '{self.user}' does not have full access to depot directory '{depot_dir}'"

		return result


@dataclass()
class OpsiUsersCheck(Check):
	id: str = "opsi_users"
	name: str = "OPSI Users"
	description: str = "Check OPSI users."
	documentation: str = f"""
		## {name} [{id}]

		Checks if opsi depot user and opsiconfd user exist and are configured correctly.
		If the system is part of a domain, it checks if the users are domain users.
		Searches sssd, winbind, ldap in /etc/nsswitch.conf to determine the domain bind.
	"""
	depot_check: bool = True

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No problems found with OPSI users.",
			check_status=CheckStatus.OK,
		)

		depot_user = opsi_config.get("depot_user", "username")
		opsiconfd_user = config.run_as_user
		for user in (depot_user, opsiconfd_user):
			self.add_partial_checks(OpsiUserCheck(user=user, login_allowed=user == opsiconfd_user, must_own_home=user != depot_user))

		return result


opsi_users_check = OpsiUsersCheck()

# getent passwd does not work on UCS systems for LDAP users
# and univention-ldapsearch is only available for root
# so we skip the opsi users check on UCS systems
if not is_ucs():
	check_manager.register(opsi_users_check)
