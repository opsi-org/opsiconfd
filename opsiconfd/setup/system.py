# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd - setup
"""

import grp
import os
import pwd
import resource
import string
import subprocess
from pathlib import Path

import psutil
from opsicommon.server.setup import (
	add_user_to_group,
	create_group,
	create_user,
	modify_user,
	set_primary_group,
)
from opsicommon.server.setup import setup_users_and_groups as po_setup_users_and_groups
from opsicommon.system.info import is_ucs
from rich import print as rich_print

from opsiconfd.config import OPSICONFD_HOME, config, get_server_role, opsi_config
from opsiconfd.logging import logger, secret_filter
from opsiconfd.utils import get_random_string, running_in_docker
from opsiconfd.utils.ucs import get_root_dn, get_ucs_admin_user


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
		except Exception as err:
			logger.warning("Failed to set RLIMIT_NOFILE: %s", err)
	logger.info("Maximum number of open file descriptors: %s", soft_limit)

	if not running_in_docker():
		try:
			proc_somaxconn = "/proc/sys/net/core/somaxconn"
			with open(proc_somaxconn, "r", encoding="ascii") as file:
				somaxconn = int(file.read().strip())
			if somaxconn < config.socket_backlog:
				logger.info("Setting %s to %s", proc_somaxconn, config.socket_backlog)
				with open(proc_somaxconn, "w", encoding="ascii") as file:
					file.write(str(config.socket_backlog))
		except OSError as err:
			logger.warning("Failed to set %s: %s", proc_somaxconn, err)


def create_ucs_group(
	name: str, description: str, ucs_root_dn: str, ucs_user: str | None, ucs_pwd: str | None, interactive: bool = False
) -> None:
	if interactive:
		rich_print(f"Creating group {name}")
	logger.info(f"Creating group {name}")
	cmd = [
		"udm",
		"groups/group",
		"create",
		"--position",
		f"cn=groups,{ucs_root_dn}",
		"--set",
		f"name={name}",
		"--set",
		f"description={description}",
		"--ignore_exists",
	]
	if ucs_user and ucs_pwd:
		cmd.append("--binddn")
		cmd.append(ucs_user)
		cmd.append("--bindpwd")
		cmd.append(ucs_pwd)
	logger.debug(cmd)
	try:
		subprocess.check_output(cmd, timeout=30)
	except subprocess.CalledProcessError as err:
		if interactive:
			rich_print(f"[b][red]Could not create group: {name}[red][/b]")
		logger.error("Could not create group: %s", name)
		logger.error(err)


def create_ucs_user(
	username: str,
	description: str,
	home: str,
	group: str,
	ucs_root_dn: str,
	password: str | None,
	ucs_user: str | None,
	ucs_pwd: str | None,
	interactive: bool = False,
) -> None:
	if interactive:
		rich_print(f"Creating user {username}")
	logger.info(f"Creating user {username}")
	if not password:
		password = get_random_string(32, alphabet=string.ascii_letters + string.digits, mandatory_alphabet="/^@?-")
	cmd = [
		"udm",
		"users/user",
		"create",
		"--position",
		f"cn=users,{ucs_root_dn}",
		"--set",
		f"username={username}",
		"--set",
		f"description={description}",
		"--set",
		f"primaryGroup=cn={group},cn=groups,{ucs_root_dn}",
		"--set",
		f"unixhome={home}",
		"--set",
		f"lastname={username}",
		"--set",
		f"password={password}",
		"--set",
		"overridePWLength=1",
		"--ignore_exists",
	]
	if ucs_user and ucs_pwd:
		cmd.append("--binddn")
		cmd.append(ucs_user)
		cmd.append("--bindpwd")
		cmd.append(ucs_pwd)
	logger.debug(cmd)
	try:
		subprocess.check_output(cmd, timeout=30)
	except subprocess.CalledProcessError as err:
		if interactive:
			rich_print(f"[b][red]Could not create user: {username}[red][/b]")
		logger.error("Could not create user: %s", username)
		logger.error(err)


def setup_ucs_users_and_groups(interactive: bool = False) -> bool:
	ucs_root_dn = get_root_dn()
	admingroup = opsi_config.get("groups", "admingroup")
	fileadmingroup = opsi_config.get("groups", "fileadmingroup")
	depot_user = opsi_config.get("depot_user", "username")
	opsiconfd_user = config.run_as_user

	ucs_admin_dn, ucs_password = get_ucs_admin_user(interactive)
	if ucs_password:
		secret_filter.add_secrets(ucs_password)

	if not ucs_admin_dn and get_server_role() not in ("domaincontroller_prim", "domaincontroller_master"):
		try:
			grp.getgrnam(admingroup)
			grp.getgrnam(fileadmingroup)
			grp.getgrnam(depot_user)
			grp.getgrnam(opsiconfd_user)
			return True
		except KeyError:
			logger.warning("User setup is not possible because we need adminuser and password.")
			logger.warning("Users and groups are temporarily created locally and then created in the domain by the join script.")
			logger.warning("Please make sure that users and groups no longer exist locally after the join script was successful.")
			logger.warning("Tip: This is also checked by the 'opsiconfd health check'.")
			return False

	try:
		grp.getgrnam(admingroup)
	except KeyError:
		create_ucs_group(admingroup, "opsi admin group", ucs_root_dn, ucs_admin_dn, ucs_password)
	try:
		grp.getgrnam(fileadmingroup)
	except KeyError:
		create_ucs_group(fileadmingroup, "opsi fileadmin group", ucs_root_dn, ucs_admin_dn, ucs_password)
	try:
		grp.getgrnam(depot_user)
	except KeyError:
		create_ucs_user(depot_user, "opsi depot user", "/var/lib/opsi", fileadmingroup, ucs_root_dn, None, ucs_admin_dn, ucs_password)
	try:
		grp.getgrnam(opsiconfd_user)
	except KeyError:
		create_ucs_user(
			opsiconfd_user, "opsi configuration daemon user", OPSICONFD_HOME, fileadmingroup, ucs_root_dn, None, ucs_admin_dn, ucs_password
		)
	return True


def setup_users_and_groups(interactive: bool = False, backend_available: bool = True) -> None:
	logger.info("Setup users and groups")
	logger.debug("Is UCS? %s", is_ucs())
	logger.debug("Is interactive? %s", interactive)
	if is_ucs():
		logger.info("UCS detected.")
		if setup_ucs_users_and_groups(interactive):
			return

	po_setup_users_and_groups(ignore_errors=True)
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

	if user:
		# Follow symlinks
		expected_home = Path(OPSICONFD_HOME).resolve()
		user_home = Path(user.pw_dir).resolve()
		if user_home != expected_home:
			try:
				modify_user(username=config.run_as_user, home=OPSICONFD_HOME)
			except Exception as err:
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
				except Exception as err:
					# Could be a user in active directory / ldap
					logger.debug(
						"Failed to set primary group of %s to %s: %s", user.pw_name, opsi_config.get("groups", "fileadmingroup"), err
					)
		except KeyError:
			logger.debug("Group not found: %s", groupname)

	server_role = get_server_role()
	if server_role != "configserver":
		return

	if not backend_available:
		return

	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()
	username = opsi_config.get("depot_user", "username")
	try:
		backend.user_getCredentials(username)
	except Exception as err:
		logger.warning("Failed to get credentials for user %s: %s, setting new random password", username, err)
		backend.user_setCredentials(
			username, get_random_string(32, alphabet=string.ascii_letters + string.digits, mandatory_alphabet="/^@?-")
		)


def systemd_running() -> bool:
	for proc in psutil.process_iter():
		if proc.name() == "systemd":
			return True
	return False


def setup_systemd() -> None:
	if not systemd_running():
		logger.debug("Systemd not running")
		return

	logger.info("Setup systemd")
	subprocess.check_output(["systemctl", "daemon-reload"])
	subprocess.check_output(["systemctl", "enable", "opsiconfd.service"])


def set_unprivileged_port_start(port: int) -> None:
	conf = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	port_start = int(conf.read_text(encoding="ascii"))
	if port_start > port:
		logger.notice("Setting ip_unprivileged_port_start to %d", port)
		conf.write_text(str(port), encoding="ascii")
