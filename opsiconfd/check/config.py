# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from __future__ import annotations

import grp
import os
import pwd
import re
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
from opsiconfd.check.cache import check_cache
from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult, exc_to_result
from opsiconfd.config import OPSICONFD_HOME, config, opsi_config
from opsiconfd.logging import logger


@check_cache("run_as_user")
def check_run_as_user() -> CheckResult:
	"""
	## Run as user
	Checks the system user running opsiconfd.
	Checks for group membership and home directory.
	"""
	result = CheckResult(
		check_id="run_as_user",
		check_name="Run as user",
		check_description="Check system user running opsiconfd",
		message=f"No issues found with user '{config.run_as_user}'.",
	)

	with exc_to_result(result):
		user = pwd.getpwnam(config.run_as_user)
		partial_result = PartialCheckResult(
			check_id="run_as_user:home_directory",
			check_name=f"Home directory of user '{config.run_as_user}'",
			check_status=CheckStatus.OK,
			message=(f"Home directory of user '{config.run_as_user}' is {user.pw_dir}"),
			details={"user": config.run_as_user, "home_directory": user.pw_dir},
		)
		if Path(user.pw_dir).resolve() != Path(OPSICONFD_HOME).resolve():
			partial_result.check_status = CheckStatus.WARNING

		result.add_partial_result(partial_result)

		gids = os.getgrouplist(user.pw_name, user.pw_gid)
		for groupname in ("shadow", opsi_config.get("groups", "admingroup"), opsi_config.get("groups", "fileadmingroup")):
			logger.debug("Processing group %s", groupname)
			partial_result = PartialCheckResult(
				check_id=f"run_as_user:group_membership:{groupname}",
				check_name=f"Group membership of user '{config.run_as_user}' in group '{groupname}'",
				check_status=CheckStatus.OK,
				message=(f"User '{config.run_as_user}' is a member of group '{groupname}'"),
				details={"user": config.run_as_user, "group": groupname, "primary": False},
			)
			try:
				group = grp.getgrnam(groupname)
				partial_result.details["primary"] = group.gr_gid == user.pw_gid
				if partial_result.details["primary"]:
					partial_result.message += " (primary)"
				if group.gr_gid not in gids:
					partial_result.check_status = CheckStatus.ERROR
					partial_result.message = f"User '{config.run_as_user}' is not a member of group '{groupname}'."
				elif groupname == opsi_config.get("groups", "fileadmingroup") and user.pw_gid != group.gr_gid:
					partial_result.check_status = CheckStatus.WARNING
					partial_result.message = f"Group '{groupname}' is not the primary group of user '{config.run_as_user}'."
			except KeyError:
				logger.debug("Group not found: %s", groupname)
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"Group '{groupname}' not found."
			result.add_partial_result(partial_result)

	if result.check_status != CheckStatus.OK:
		result.message = f"Some issues found with user '{config.run_as_user}'."
	return result


@check_cache("opsiconfd_config")
def check_opsiconfd_config() -> CheckResult:
	"""
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
	result = CheckResult(
		check_id="opsiconfd_config",
		check_name="Opsiconfd config",
		check_description="Check opsiconfd configuration",
		message="No issues found in the configuration.",
	)
	with exc_to_result(result):
		issues = 0
		for attribute in "log-level-stderr", "log-level-file", "log-level":
			value = getattr(config, attribute.replace("-", "_"))
			level_name = LEVEL_TO_NAME[OPSI_LEVEL_TO_LEVEL[value]]
			partial_result = PartialCheckResult(
				check_id=f"opsiconfd_config:{attribute}",
				check_name=f"Config {attribute}",
				message=f"Log level setting '{attribute}={level_name}' is suitable for productive use.",
				details={"config": attribute, "value": value},
			)
			if value >= LOG_TRACE:
				issues += 1
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"Log level setting '{attribute}={level_name}' is much to high for productive use."
			elif value >= LOG_DEBUG:
				issues += 1
				partial_result.check_status = CheckStatus.WARNING
				partial_result.message = f"Log level setting '{attribute}={level_name}' is to high for productive use."
			result.add_partial_result(partial_result)

		partial_result = PartialCheckResult(
			check_id="opsiconfd_config:debug-options",
			check_name="Config debug-options",
			message="No debug options are set.",
			details={"config": "debug-options", "value": config.debug_options},
		)
		if config.debug_options:
			issues += 1
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"The following debug options are set: {', '.join(config.debug_options)}."
		result.add_partial_result(partial_result)

		partial_result = PartialCheckResult(
			check_id="opsiconfd_config:profiler",
			check_name="Config profiler",
			message="Profiler is not enabled.",
			details={"config": "profiler", "value": config.profiler},
		)
		if config.profiler:
			issues += 1
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = "Profiler is enabled."
		result.add_partial_result(partial_result)

		partial_result = PartialCheckResult(
			check_id="opsiconfd_config:run-as-user",
			check_name="Config run-as-user",
			message=f"Opsiconfd is running as user {config.run_as_user}.",
			details={"config": "run-as-user", "value": config.run_as_user},
		)
		if config.run_as_user == "root":
			issues += 1
			partial_result.check_status = CheckStatus.ERROR
		result.add_partial_result(partial_result)

		partial_result = PartialCheckResult(
			check_id="opsiconfd_config:acl-self-for-all",
			check_name="Do acls allow self for .*",
			message="'self' is not allowed for '.*'.",
			details={},
		)
		fallback_acl = re.compile(".*")
		for acl in read_acl_file(config.acl_file):
			if not acl.method_re == fallback_acl:
				continue
			if acl.type == "self":
				issues += 1
				partial_result.message = "'self' is allowed for '.*'."
				partial_result.check_status = CheckStatus.ERROR
				break
		result.add_partial_result(partial_result)

		if issues > 0:
			result.message = f"{issues} issues found in the configuration."

	return result


@check_cache("opsi_config")
def check_opsi_config() -> CheckResult:
	"""
	## OPSI Configuration

	Here we check whether certain configurations deviate from the standard.
	If this is the case, a warning is issued.
	An error is output if the value does not exist.

	* `opsiclientd.global.verify_server_cert` must be activated.
	"""
	result = CheckResult(
		check_id="opsi_config",
		check_name="OPSI Configuration",
		check_description="Check opsi configuration state",
		message="No issues found in the opsi configuration.",
	)
	with exc_to_result(result):
		backend = get_unprotected_backend()
		check_configs: dict[str, Any] = {"opsiclientd.global.verify_server_cert": {"default_value": [True], "upgrade_issue": "4.3"}}
		count = 0
		for key, check_data in check_configs.items():
			default_value = check_data["default_value"]
			partial_result = PartialCheckResult(
				check_id=f"opsi_config:{key}",
				check_name=f"OPSI Configuration {key}",
				details={"config_id": key, "deafult_value": default_value},
			)
			conf = backend.config_getObjects(id=key)
			try:
				if conf[0].defaultValues == default_value:
					partial_result.check_status = CheckStatus.OK
					partial_result.message = f"Configuration {key} is set to default."
				else:
					partial_result.check_status = CheckStatus.WARNING
					partial_result.message = f"Configuration {key} is set to {conf[0].defaultValues} - default is {default_value}."
					partial_result.upgrade_issue = check_data["upgrade_issue"]
					count = count + 1
				partial_result.details["value"] = conf[0].defaultValues
				result.add_partial_result(partial_result)
			except IndexError:
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"Configuration {key} does not exist."
				partial_result.details["value"] = None
				result.add_partial_result(partial_result)
				partial_result.upgrade_issue = check_data["upgrade_issue"]
				count = count + 1
				continue
		if count > 0:
			result.message = f"{count} issues found in the opsi configuration."
	return result
