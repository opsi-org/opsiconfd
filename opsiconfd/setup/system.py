# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - setup
"""

import grp
import os
import pwd
import resource
import subprocess

import psutil
from opsicommon.server.setup import (  # type: ignore[import]
	add_user_to_group,
	create_group,
	create_user,
	modify_user,
	set_primary_group,
)

from opsiconfd.config import OPSICONFD_HOME, config, opsi_config
from opsiconfd.logging import logger


def setup_limits() -> None:
	logger.info("Setup system limits")
	# The hard limit is the maximum value that is allowed for the soft limit. Any changes to the hard limit require root access.
	# The soft limit is the value that Linux uses to limit the system resources for running processes.
	# The soft limit cannot be greater than the hard limit.
	(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
	if 0 < soft_limit < 10000:
		try:
			# ulimit -n 10000
			soft_limit = 10000
			resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, max(hard_limit, soft_limit)))
			(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Failed to set RLIMIT_NOFILE: %s", err)
	logger.info("Maximum number of open file descriptors: %s", soft_limit)


def setup_users_and_groups() -> None:
	logger.info("Setup users and groups")

	if config.run_as_user == "root":
		return

	user = None
	try:
		user = pwd.getpwnam(config.run_as_user)
	except KeyError:
		# User not found
		create_user(
			username=config.run_as_user,
			primary_groupname=opsi_config.get("groups", "fileadmingroup"),
			home=OPSICONFD_HOME,
			shell="/bin/bash",
			system=True,
		)
		user = pwd.getpwnam(config.run_as_user)

	if user and user.pw_dir != OPSICONFD_HOME:
		try:
			modify_user(username=config.run_as_user, home=OPSICONFD_HOME)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(
				"Failed to change home directory of user %r (%s). Should be %r but is %r, please change manually.",
				config.run_as_user,
				err,
				OPSICONFD_HOME,
				user.pw_dir,
			)

	try:
		grp.getgrnam("shadow")
	except KeyError:
		create_group(groupname="shadow", system=True)

	gids = os.getgrouplist(user.pw_name, user.pw_gid)
	for groupname in ("shadow", opsi_config.get("groups", "admingroup"), opsi_config.get("groups", "fileadmingroup")):
		logger.debug("Processing group %s", groupname)
		try:
			group = grp.getgrnam(groupname)
			if group.gr_gid not in gids:
				add_user_to_group(config.run_as_user, groupname)
			if groupname == opsi_config.get("groups", "fileadmingroup") and user.pw_gid != group.gr_gid:
				try:
					set_primary_group(user.pw_name, opsi_config.get("groups", "fileadmingroup"))
				except Exception as err:  # pylint: disable=broad-except
					# Could be a user in active directory / ldap
					logger.debug(
						"Failed to set primary group of %s to %s: %s", user.pw_name, opsi_config.get("groups", "fileadmingroup"), err
					)
		except KeyError:
			logger.debug("Group not found: %s", groupname)


def setup_systemd() -> None:
	systemd_running = False
	for proc in psutil.process_iter():
		if proc.name() == "systemd":
			systemd_running = True
			break
	if not systemd_running:
		logger.debug("Systemd not running")
		return

	logger.info("Setup systemd")
	subprocess.check_output(["systemctl", "daemon-reload"])
	subprocess.check_output(["systemctl", "enable", "opsiconfd.service"])
