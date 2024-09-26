# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """


import grp
import os
import pwd
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opsicommon.logging.constants import (
	LEVEL_TO_NAME,
	LOG_DEBUG,
	LOG_TRACE,
	OPSI_LEVEL_TO_LEVEL,
)

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.backend.auth import read_acl_file
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager, exc_to_result
from opsiconfd.config import OPSICONFD_HOME, config, opsi_config
from opsiconfd.logging import logger


@dataclass()
class HomeDirectoryCheck(Check):
	id: str = "home_directory"
	name: str = "Home directory"
	description: str = "Check home directory of opsiconfd user"
	documentation: str = """
## Home directory
Checks the home directory of the system user running opsiconfd.
"""
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(check=self, check_status=CheckStatus.OK)
		with exc_to_result(result):
			user = pwd.getpwnam(config.run_as_user)
			self.name = f"Home directory of user '{config.run_as_user}'"
			result.message = f"Home directory of user '{config.run_as_user}' is {user.pw_dir}"
			result.details = {"user": config.run_as_user, "home_directory": user.pw_dir}
			if Path(user.pw_dir).resolve() != Path(OPSICONFD_HOME).resolve():
				result.check_status = CheckStatus.WARNING

			return result


@dataclass()
class GroupMembershipCheck(Check):
	id: str = "group_membership"
	name: str = "Group membership"
	description: str = "Check group membership of opsiconfd user"
	documentation: str = """
## Group membership
Checks the group membership of the system user running opsiconfd.
"""
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(check=self, check_status=CheckStatus.OK)
		with exc_to_result(result):
			user = pwd.getpwnam(config.run_as_user)
			gids = os.getgrouplist(user.pw_name, user.pw_gid)
			for groupname in ("shadow", opsi_config.get("groups", "admingroup"), opsi_config.get("groups", "fileadmingroup")):
				self.name = f"Group membership of user '{config.run_as_user}' in group '{groupname}'"
				self.details = {"user": config.run_as_user, "group": groupname, "primary": False}

				result.message = f"User '{config.run_as_user}' is a member of group '{groupname}'"
				result.details = self.details
				try:
					group = grp.getgrnam(groupname)
					result.details["primary"] = group.gr_gid == user.pw_gid
					if result.details["primary"]:
						result.message += " (primary)"
					if group.gr_gid not in gids:
						result.check_status = CheckStatus.ERROR
						result.message = f"User '{config.run_as_user}' is not a member of group '{groupname}'."
					elif groupname == opsi_config.get("groups", "fileadmingroup") and user.pw_gid != group.gr_gid:
						result.check_status = CheckStatus.WARNING
						result.message = f"Group '{groupname}' is not the primary group of user '{config.run_as_user}'."
				except KeyError:
					logger.debug("Group not found: %s", groupname)
					result.check_status = CheckStatus.ERROR
					result.message = f"Group '{groupname}' not found."
		return result


@dataclass()
class RunAsUserCheck(Check):
	id: str = "opsiconfd_config:run_as_user"
	name: str = "Run as user"
	description: str = "Check system user running opsiconfd"
	documentation: str = """
## Run as user
Checks the system user running opsiconfd.
Checks for group membership and home directory.
"""
	depot_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			check_status=CheckStatus.OK,
			message=f"No issues found with user '{config.run_as_user}'.",
		)

		return result


@dataclass()
class LogLevelCheck(Check):
	id: str = "opsiconfd_config:log-level"
	name: str = "Log level"
	description: str = "Check log level of opsiconfd"
	partial_check: bool = True
	attribute: str = "log-level"

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"opsiconfd_config:{self.attribute}"
		self.name = f"Config {self.attribute}"

	def check(self) -> CheckResult:
		result = CheckResult(check=self, check_status=CheckStatus.OK, message="Log level is suitable for productive use.")
		with exc_to_result(result):
			value = getattr(config, self.attribute.replace("-", "_"))
			level_name = LEVEL_TO_NAME[OPSI_LEVEL_TO_LEVEL[value]]
			result.message = f"Log level setting '{self.attribute}={level_name}' is suitable for productive use."
			result.details = {"config": self.attribute, "value": value}

			if value >= LOG_TRACE:
				result.check_status = CheckStatus.ERROR
				result.message = f"Log level setting '{self.attribute}={level_name}' is much to high for productive use."
			elif value >= LOG_DEBUG:
				result.check_status = CheckStatus.WARNING
				result.message = f"Log level setting '{self.attribute}={level_name}' is to high for productive use."
		return result


@dataclass()
class DebugOptionsCheck(Check):
	id: str = "opsiconfd_config:debug_options"
	name: str = "Debug options"
	description: str = "Check debug options of opsiconfd"
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			check_status=CheckStatus.OK,
			message="No debug options are set.",
			details={"config": "debug-options", "value": config.debug_options},
		)
		with exc_to_result(result):
			if config.debug_options:
				result.check_status = CheckStatus.ERROR
				result.message = f"The following debug options are set: {', '.join(config.debug_options)}."
		return result


@dataclass()
class ProfilerCheck(Check):
	id: str = "opsiconfd_config:profiler"
	name: str = "Profiler"
	description: str = "Check profiler of opsiconfd"
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(check=self, check_status=CheckStatus.OK, message="Profiler is not enabled.")
		with exc_to_result(result):
			if config.profiler:
				result.check_status = CheckStatus.ERROR
				result.message = "Profiler is enabled."
		return result


@dataclass()
class AclSelfForAllCheck(Check):
	id: str = "opsiconfd_config:acl_self_for_all"
	name: str = "ACL self for all"
	description: str = "Check ACL self for all in opsiconfd"
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(check=self, check_status=CheckStatus.OK, message="'self' is not allowed for '.*'.")
		with exc_to_result(result):
			fallback_acl = re.compile(".*")
			for acl in read_acl_file(config.acl_file):
				if not acl.method_re == fallback_acl:
					continue
				if acl.type == "self":
					result.check_status = CheckStatus.ERROR
					result.message = "'self' is allowed for '.*'."
					break
		return result


@dataclass()
class OpsiconfdConfigRunAsUser(Check):
	id: str = "opsiconfd_config:run_as_user"
	name: str = "Run as user"
	description: str = "Check system user running opsiconfd"
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			check_status=CheckStatus.OK,
			message=f"No issues found with user '{config.run_as_user}'.",
		)

		if config.run_as_user == "root":
			result.message = "The opsiconfd process is run as user root."
			result.check_status = CheckStatus.ERROR

		return result


@dataclass()
class OpsiconfdConfigCheck(Check):
	id: str = "opsiconfd_config"
	name: str = "Opsiconfd config"
	description: str = "Check opsiconfd configuration"
	documentation: str = """
## Opsiconfd config
This check examines the configuration of the opsiconfd service by checking the following values:

* `log-level-stderr`, `log-level-file`, `log-level`
	* If the log level is too high for a productive environment, then performance problems may occur.
		For this reason, a warning is issued at a log level of 7 and an error is issued at log level 8 or higher.
* `debug-options`
	* If a debug option is active, this is considered an error, as it can lead to performance problems in productive environments.
* `profiler`
	* The profiler should also be deactivated for performance reasons. An active profiler will also result in an error output.
* `run-as-user`
	* Running the service opsiconfd as user root will be evaluated as an error, because root has too many rights on the system.
* `acl-self-for-all`
	* Enabling `self` for `.*` results in an error, as some objects do not have an attribute corresponding to a client.
"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			check_status=CheckStatus.OK,
			message="No issues found in the configuration.",
		)

		return result


@dataclass()
class OpsiConfigValueCheck(Check):
	id: str = "opsi_config_value"
	name: str = "OPSI Configuration Value"
	description: str = "Check opsi configuration value"
	key: str = ""
	default_value: Any = None
	upgrade_issue: str = ""
	partial_check: bool = True

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"opsi_config:{self.key}"
		self.name = f"Config {self.key}"

	def check(self) -> CheckResult:
		result = CheckResult(check=self, check_status=CheckStatus.OK)
		with exc_to_result(result):
			backend = get_unprotected_backend()
			conf = backend.config_getObjects(id=key)
			try:
				if conf[0].defaultValues == self.default_value:
					result.check_status = CheckStatus.OK
					result.message = f"Configuration {key} is set to default."
				else:
					result.check_status = CheckStatus.WARNING
					result.message = f"Configuration {key} is set to {conf[0].defaultValues} - default is {self.default_value}."
					result.upgrade_issue = self.upgrade_issue

				result.details["value"] = conf[0].defaultValues
			except IndexError:
				result.check_status = CheckStatus.ERROR
				result.message = f"Configuration {key} does not exist."
				result.details["value"] = None
				result.upgrade_issue = check_data["upgrade_issue"]

		return result


@dataclass()
class OpsiConfigCheck(Check):
	id: str = "opsi_config"
	name: str = "OPSI Configuration"
	description: str = "Check opsi configuration state"
	documentation: str = """
## OPSI Configuration

Here we check whether certain configurations deviate from the standard.
If this is the case, a warning is issued.
An error is output if the value does not exist.

* `opsiclientd.global.verify_server_cert` must be activated.
"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			check_status=CheckStatus.OK,
			message="No issues found in the opsi configuration.",
		)

		return result


run_as_user_check = RunAsUserCheck(partial_checks=[HomeDirectoryCheck(), GroupMembershipCheck()])
opsiconfd_config_check = OpsiconfdConfigCheck(
	partial_checks=[DebugOptionsCheck(), ProfilerCheck(), AclSelfForAllCheck(), OpsiconfdConfigRunAsUser()]
)
for attribute in "log-level-stderr", "log-level-file", "log-level":
	opsiconfd_config_check.add_partial_checks(LogLevelCheck(attribute=attribute))
opsi_config_check = OpsiConfigCheck()
check_configs: dict[str, Any] = {"opsiclientd.global.verify_server_cert": {"default_value": [True], "upgrade_issue": "4.3"}}
for key, check_data in check_configs.items():
	opsi_config_check.add_partial_checks(
		OpsiConfigValueCheck(key=key, default_value=check_data["default_value"], upgrade_issue=check_data["upgrade_issue"])
	)
check_manager.register(run_as_user_check, opsiconfd_config_check, opsi_config_check)
