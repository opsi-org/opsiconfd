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
import time
import getpass
import resource
import subprocess
from pathlib import Path
import psutil

from OPSI.Config import OPSI_ADMIN_GROUP, FILE_ADMIN_GROUP
from OPSI.setup import (
	setup_users_and_groups as po_setup_users_and_groups,
	add_user_to_group, create_user, set_primary_group, create_group
)
from OPSI.System.Posix import getLocalFqdn, locateDHCPDConfig
from OPSI.Util.Task.InitializeBackend import initializeBackends
from OPSI.Util.Task.Rights import PermissionRegistry, FilePermission, set_rights
from OPSI.System import get_subprocess_environment

from .logging import logger
from .config import config
from .backend import get_backend
from .grafana import setup_grafana
from .statistics import setup_metric_downsampling
from .ssl import setup_ssl, setup_ssl_file_permissions

def setup_limits():
	logger.info("Setup system limits")
	# The hard limit is the maximum value that is allowed for the soft limit. Any changes to the hard limit require root access.
	# The soft limit is the value that Linux uses to limit the system resources for running processes.
	# The soft limit cannot be greater than the hard limit.
	(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
	if 0 < soft_limit < 10000:
		try:
			# ulimit -n 10000
			resource.setrlimit(resource.RLIMIT_NOFILE, (10000, hard_limit))
			(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
		except Exception as exc: # pylint: disable=broad-except
			logger.warning("Failed to set RLIMIT_NOFILE: %s", exc)
	logger.info("Maximum number of open file descriptors: %s", soft_limit)

def setup_users_and_groups():
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
			primary_groupname=FILE_ADMIN_GROUP,
			home="/var/lib/opsi",
			shell="/bin/bash",
			system=True
		)
		user = pwd.getpwnam(config.run_as_user)

	try:
		grp.getgrnam("shadow")
	except KeyError:
		create_group(
			groupname="shadow",
			system=True
		)

	gids = os.getgrouplist(user.pw_name, user.pw_gid)
	for groupname in ("shadow", OPSI_ADMIN_GROUP, FILE_ADMIN_GROUP):
		logger.debug("Processing group %s", groupname)
		try:
			group = grp.getgrnam(groupname)
			if group.gr_gid not in gids:
				add_user_to_group(config.run_as_user, groupname)
			if groupname == FILE_ADMIN_GROUP and user.pw_gid != group.gr_gid:
				try:
					set_primary_group(user.pw_name, FILE_ADMIN_GROUP)
				except Exception as err: # pylint: disable=broad-except
					# Could be a user in active directory / ldap
					logger.debug("Failed to set primary group of %s to %s: %s", user.pw_name, FILE_ADMIN_GROUP, err)
		except KeyError:
			logger.debug("Group not found: %s", groupname)

def setup_files():
	log_dir = os.path.dirname(config.log_file)
	if not os.path.isdir(log_dir):
		os.makedirs(log_dir)

def setup_file_permissions():
	logger.info("Setup file permissions")

	dhcpd_config_file = locateDHCPDConfig("/etc/dhcp3/dhcpd.conf")
	permissions = (
		FilePermission("/etc/shadow", None, "shadow", 0o640),
		FilePermission("/var/log/opsi/opsiconfd/opsiconfd.log", config.run_as_user, OPSI_ADMIN_GROUP, 0o660),
		# On many systems dhcpd is running as unprivileged user (i.e. dhcpd)
		# This user needs read permission
		FilePermission(dhcpd_config_file, config.run_as_user, OPSI_ADMIN_GROUP, 0o664)
	)
	PermissionRegistry().register_permission(*permissions)
	for permission in permissions:
		set_rights(permission.path)

	set_rights("/etc/opsi")
	setup_ssl_file_permissions()

	for path in (
		"/var/log/opsi/bootimage", "/var/log/opsi/clientconnect", "/var/log/opsi/instlog",
		"/var/log/opsi/opsiconfd", "/var/log/opsi/userlogin", "/var/lib/opsi/depot",
		"/var/lib/opsi/ntfs-images", "/var/lib/opsi/repository"
	):
		try:
			path = Path(path)
			if path.is_dir() and path.owner() != config.run_as_user:
				set_rights(str(path))
		except KeyError as err:
			logger.warning("Failed to set permissions on '%s': %s", str(path), err)


def setup_systemd():
	systemd_running = False
	for proc in psutil.process_iter():
		if proc.name() == "systemd":
			systemd_running = True
			break
	if not systemd_running:
		logger.debug("Systemd not running")
		return

	logger.info("Setup systemd")
	subprocess.run(["systemctl", "daemon-reload"], env=get_subprocess_environment(), capture_output=True) # pylint: disable=subprocess-run-check
	subprocess.run(["systemctl", "enable", "opsiconfd.service"], env=get_subprocess_environment(), capture_output=True) # pylint: disable=subprocess-run-check

def setup_backend():
	fqdn = getLocalFqdn()
	try:
		backend = get_backend()
		backend.host_getObjects(type='OpsiDepotserver', id=fqdn) # pylint: disable=no-member
	except Exception as err: # pylint: disable=broad-except
		logger.debug(err)

	logger.info("Setup backend")
	initializeBackends()

def cleanup_log_files():
	logger.info("Cleanup log files")
	now = time.time()
	min_mtime = now - 3600 * 24 * 30 # 30 days
	log_dir = os.path.dirname(config.log_file)
	if not os.path.isdir(log_dir):
		return
	links = []
	for filename in os.listdir(log_dir):
		try:
			file = os.path.join(log_dir, filename)
			if os.path.islink(file):
				links.append(file)
			elif os.path.isfile(file) and os.path.getmtime(file) < min_mtime:
				logger.info("Deleting old log file: %s", file)
				os.remove(file)
		except Exception as err: # pylint: disable=broad-except
			logger.warning(err)

	for link in links:
		try:
			dst = os.path.realpath(link)
			if not os.path.exists(dst):
				os.unlink(link)
		except Exception as err: # pylint: disable=broad-except
			logger.warning(err)

def setup(full: bool = True): # pylint: disable=too-many-branches
	logger.notice("Running opsiconfd setup")

	skip_setup = config.skip_setup or []
	if skip_setup:
		logger.notice("Skipping setup tasks: %s", ", ".join(skip_setup))

	if "all" in skip_setup:
		return

	if not config.run_as_user:
		config.run_as_user = getpass.getuser()
	if not "limits" in skip_setup:
		setup_limits()
	if full:
		if not "users" in skip_setup and not "groups" in skip_setup:
			po_setup_users_and_groups()
			setup_users_and_groups()
		if not "backend" in skip_setup:
			try:
				setup_backend()
			except Exception as err: # pylint: disable=broad-except
				# This can happen during package installation
				# where backend config files are missing
				logger.debug("Failed to setup backend: %s", err, exc_info=True)
				logger.warning("Failed to setup backend: %s", err)
		if not "files" in skip_setup:
			setup_files()
		#po_setup_file_permissions() # takes very long with many files in /var/lib/opsi
		if not "systemd" in skip_setup:
			setup_systemd()
	else:
		if not "users" in skip_setup and not "groups" in skip_setup:
			setup_users_and_groups()
	if not "file_permissions" in skip_setup:
		# Always correct file permissions (run_as_user could be changed)
		setup_file_permissions()
	if not "log_files" in skip_setup:
		cleanup_log_files()
	if not "grafana" in skip_setup:
		try:
			setup_grafana()
		except Exception as err: # pylint: disable=broad-except
			logger.warning("Failed to setup grafana: %s", err)

	if not "metric_downsampling" in skip_setup:
		try:
			setup_metric_downsampling()
		except Exception as err: # pylint: disable=broad-except
			logger.warning("Faild to setup redis downsampling: %s", err)

	if not "ssl" in skip_setup:
		try:
			setup_ssl()
		except Exception as err: # pylint: disable=broad-except
			# This can fail if fqdn is not valid
			logger.error("Failed to setup ssl: %s", err)
