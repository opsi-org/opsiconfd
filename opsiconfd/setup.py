# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - setup
"""

import getpass
import grp
import os
import pwd
import resource
import subprocess
import time
from pathlib import Path

import psutil
from OPSI.System.Posix import (  # type: ignore[import]
	getNetworkConfiguration,
	locateDHCPDConfig,
)
from opsicommon.objects import OpsiConfigserver  # type: ignore[import]
from opsicommon.server.rights import (  # type: ignore[import]
	DirPermission,
	FilePermission,
	PermissionRegistry,
	set_rights,
)
from opsicommon.server.setup import (  # type: ignore[import]
	add_user_to_group,
	create_group,
	create_user,
	set_primary_group,
)
from opsicommon.server.setup import (
	setup_users_and_groups as po_setup_users_and_groups,  # type: ignore[import]
)

from .application.utils import get_configserver_id
from .backend.mysql import MySQLConnection
from .backend.mysql.cleanup import cleanup_database
from .backend.mysql.schema import update_database
from .config import FQDN, OPSI_LICENSE_PATH, VAR_ADDON_DIR, config, opsi_config
from .grafana import setup_grafana
from .logging import logger
from .metrics.statistics import setup_metric_downsampling
from .ssl import setup_ssl, setup_ssl_file_permissions


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
			home="/var/lib/opsi",
			shell="/bin/bash",
			system=True,
		)
		user = pwd.getpwnam(config.run_as_user)

	try:
		grp.getgrnam("shadow")
	except KeyError:
		create_group(groupname="shadow", system=True)

	gids = os.getgrouplist(user.pw_name, user.pw_gid)
	for groupname in ("shadow", opsi_config.get("groups", "admingroup"), opsi_config.get("groups", "fileadmingroup")):
		logger.debug("Processing group %s", groupname)
		try:  # pylint: disable=loop-try-except-usage
			group = grp.getgrnam(groupname)  # pylint: disable=dotted-import-in-loop
			if group.gr_gid not in gids:
				add_user_to_group(config.run_as_user, groupname)
			if groupname == opsi_config.get("groups", "fileadmingroup") and user.pw_gid != group.gr_gid:
				try:  # pylint: disable=loop-try-except-usage
					set_primary_group(user.pw_name, opsi_config.get("groups", "fileadmingroup"))
				except Exception as err:  # pylint: disable=broad-except
					# Could be a user in active directory / ldap
					logger.debug(
						"Failed to set primary group of %s to %s: %s", user.pw_name, opsi_config.get("groups", "fileadmingroup"), err
					)
		except KeyError:
			logger.debug("Group not found: %s", groupname)


def setup_files() -> None:
	for _dir in (os.path.dirname(config.log_file), VAR_ADDON_DIR, OPSI_LICENSE_PATH):  # pylint: disable=dotted-import-in-loop
		if not os.path.isdir(_dir):  # pylint: disable=dotted-import-in-loop
			os.makedirs(_dir)  # pylint: disable=dotted-import-in-loop


def setup_file_permissions() -> None:
	logger.info("Setup file permissions")

	dhcpd_config_file = locateDHCPDConfig("/etc/dhcp3/dhcpd.conf")
	permissions = (
		FilePermission("/etc/shadow", None, "shadow", 0o640),
		FilePermission("/var/log/opsi/opsiconfd/opsiconfd.log", config.run_as_user, opsi_config.get("groups", "admingroup"), 0o660),
		# On many systems dhcpd is running as unprivileged user (i.e. dhcpd)
		# This user needs read permission
		FilePermission(dhcpd_config_file, config.run_as_user, opsi_config.get("groups", "admingroup"), 0o664),
		DirPermission(VAR_ADDON_DIR, config.run_as_user, opsi_config.get("groups", "fileadmingroup"), 0o660, 0o770),
	)
	PermissionRegistry().register_permission(*permissions)
	for permission in permissions:
		set_rights(permission.path)

	set_rights("/etc/opsi")
	setup_ssl_file_permissions()

	for path_str in (
		"/var/log/opsi/bootimage",
		"/var/log/opsi/clientconnect",
		"/var/log/opsi/instlog",
		"/var/log/opsi/opsiconfd",
		"/var/log/opsi/userlogin",
		"/var/lib/opsi/depot",
		"/var/lib/opsi/ntfs-images",
		"/var/lib/opsi/repository",
		"/var/lib/opsi/public",
		"/var/lib/opsi/workbench",
		VAR_ADDON_DIR,
	):
		try:  # pylint: disable=loop-try-except-usage
			path = Path(path_str)
			if path.is_dir() and path.owner() != config.run_as_user:
				set_rights(str(path))
		except KeyError as err:
			logger.warning("Failed to set permissions on '%s': %s", str(path), err)


def setup_systemd() -> None:
	systemd_running = False
	for proc in psutil.process_iter():  # pylint: disable=dotted-import-in-loop
		if proc.name() == "systemd":
			systemd_running = True
			break
	if not systemd_running:
		logger.debug("Systemd not running")
		return

	logger.info("Setup systemd")
	subprocess.check_output(["systemctl", "daemon-reload"])
	subprocess.check_output(["systemctl", "enable", "opsiconfd.service"])


def setup_backend() -> None:
	if opsi_config.get("host", "server-role") != "configserver":
		return

	mysql = MySQLConnection()
	mysql.connect()
	update_database(mysql)
	cleanup_database(mysql)

	if not mysql.get_idents(table="HOST", object_type=OpsiConfigserver, ace=[], filter={"type": "OpsiConfigserver"}):
		logger.notice("No configserver found in backend, creating")
		network_config = getNetworkConfiguration()
		config_server = OpsiConfigserver(
			id=get_configserver_id(),
			opsiHostKey=None,
			depotLocalUrl="file:///var/lib/opsi/depot",
			depotRemoteUrl=f"smb://{FQDN}/opsi_depot",
			depotWebdavUrl=f"webdavs://{FQDN}:4447/depot",
			repositoryLocalUrl="file:///var/lib/opsi/repository",
			repositoryRemoteUrl=f"webdavs://{FQDN}:4447/repository",
			workbenchLocalUrl="file:///var/lib/opsi/workbench",
			workbenchRemoteUrl=f"smb://{FQDN}/opsi_workbench",
			description=None,
			notes=None,
			hardwareAddress=network_config["hardwareAddress"],
			ipAddress=network_config["ipAddress"],
			inventoryNumber=None,
			networkAddress=f"{network_config['subnet']}/{network_config['netmask']}",
			maxBandwidth=0,
			isMasterDepot=True,
			masterDepotId=None,
		)
		mysql.insert_object(table="HOST", obj=config_server, ace=[], create=True, set_null=True)

	mysql.disconnect()


def cleanup_log_files() -> None:
	logger.info("Cleanup log files")
	now = time.time()
	min_mtime = now - 3600 * 24 * 30  # 30 days
	log_dir = os.path.dirname(config.log_file)
	if not os.path.isdir(log_dir):
		return
	links = []
	for filename in os.listdir(log_dir):  # pylint: disable=dotted-import-in-loop
		try:  # pylint: disable=loop-try-except-usage
			file = os.path.join(log_dir, filename)  # pylint: disable=dotted-import-in-loop
			if os.path.islink(file):  # pylint: disable=dotted-import-in-loop
				links.append(file)
			elif os.path.isfile(file) and os.path.getmtime(file) < min_mtime:  # pylint: disable=dotted-import-in-loop
				logger.info("Deleting old log file: %s", file)
				os.remove(file)  # pylint: disable=dotted-import-in-loop
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err)

	for link in links:
		try:  # pylint: disable=loop-try-except-usage
			dst = os.path.realpath(link)  # pylint: disable=dotted-import-in-loop
			if not os.path.exists(dst):  # pylint: disable=dotted-import-in-loop
				os.unlink(link)  # pylint: disable=dotted-import-in-loop
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err)


def setup(full: bool = True) -> None:  # pylint: disable=too-many-branches
	logger.notice("Running opsiconfd setup")

	if config.skip_setup:
		logger.notice("Skipping setup tasks: %s", ", ".join(config.skip_setup))

	if "all" in config.skip_setup:
		return

	if not config.run_as_user:
		config.run_as_user = getpass.getuser()
	if "limits" not in config.skip_setup:
		setup_limits()
	if "backend" not in config.skip_setup:
		try:
			setup_backend()
		except Exception as err:  # pylint: disable=broad-except
			# This can happen during package installation
			# where backend config files are missing
			logger.debug("Failed to setup backend: %s", err, exc_info=True)
			logger.warning("Failed to setup backend: %s", err, exc_info=True)
	if full:
		if "users" not in config.skip_setup and "groups" not in config.skip_setup:
			po_setup_users_and_groups(ignore_errors=True)
			setup_users_and_groups()
		if "files" not in config.skip_setup:
			setup_files()
		# po_setup_file_permissions() # takes very long with many files in /var/lib/opsi
		if "systemd" not in config.skip_setup:
			setup_systemd()
	else:
		if "users" not in config.skip_setup and "groups" not in config.skip_setup:
			setup_users_and_groups()
	if "file_permissions" not in config.skip_setup:
		# Always correct file permissions (run_as_user could be changed)
		setup_file_permissions()
	if "log_files" not in config.skip_setup:
		cleanup_log_files()
	if "grafana" not in config.skip_setup:
		try:
			setup_grafana()
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Failed to setup grafana: %s", err, exc_info=True)

	if "metric_downsampling" not in config.skip_setup:
		try:
			setup_metric_downsampling()
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Failed to setup redis downsampling: %s", err, exc_info=True)

	try:
		setup_ssl()
	except Exception as err:  # pylint: disable=broad-except
		# This can fail if fqdn is not valid
		logger.error("Failed to setup ssl: %s", err, exc_info=True)
