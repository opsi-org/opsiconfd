# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""

import os
import pwd
import grp
import getpass
import shutil
import resource
import subprocess

from OPSI.Config import OPSI_ADMIN_GROUP, FILE_ADMIN_GROUP, DEFAULT_DEPOT_USER
from OPSI.setup import setup as python_opsi_setup, get_users, get_groups, add_user_to_group

from .logging import logger
from .config import config

def setup_limits():
	# The hard limit is the maximum value that is allowed for the soft limit. Any changes to the hard limit require root access.
	# The soft limit is the value that Linux uses to limit the system resources for running processes. The soft limit cannot be greater than the hard limit.
	(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
	if (soft_limit > 0 and soft_limit < 10000):
		try:
			# ulimit -n 10000
			resource.setrlimit(resource.RLIMIT_NOFILE, (10000, hard_limit))
			(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
		except Exception as exc:
			logger.warning("Failed to set RLIMIT_NOFILE: %s", exc)
	logger.info("Maximum number of open file descriptors: %s", soft_limit)

def setup_users_and_groups():
	groups = get_groups()
	users = get_users()
	
	if config.run_as_user != "root":
		if config.run_as_user not in users:
			create_user(
				username=config.run_as_user,
				primary_groupname=FILE_ADMIN_GROUP,
				home="/var/lib/opsi",
				shell="/bin/bash",
				system=True
			)
			users = get_users()
		if "shadow" in groups and config.run_as_user not in groups["shadow"].gr_mem:
			add_user_to_group(config.run_as_user, "shadow")
		if OPSI_ADMIN_GROUP in groups and config.run_as_user not in groups[OPSI_ADMIN_GROUP].gr_mem:
			add_user_to_group(config.run_as_user, OPSI_ADMIN_GROUP)

def setup_file_permissions():
	log_dir = os.path.dirname(os.path.abspath(config.log_file))
	if log_dir.count(os.sep) > 0:
		for root, dirs, files in os.walk(log_dir):
			shutil.chown(root, config.run_as_user, OPSI_ADMIN_GROUP)
			os.chmod(root, mode=0o770)
			for item in dirs:
				shutil.chown(os.path.join(root, item), config.run_as_user, OPSI_ADMIN_GROUP)
				os.chmod(root, mode=0o770)
			for item in files:
				shutil.chown(os.path.join(root, item), config.run_as_user, OPSI_ADMIN_GROUP)
				os.chmod(root, mode=0o660)

def setup_systemd():
	subprocess.call(["systemctl", "daemon-reload"])
	subprocess.call(["systemctl", "enable", "opsiconfd.service"])

def setup(full: bool = True):
	logger.notice("Running setup")
	if not config.run_as_user:
		config.run_as_user = getpass.getuser()
	setup_limits()
	if full:
		python_opsi_setup()
		setup_users_and_groups()
		setup_file_permissions()
		setup_systemd()
