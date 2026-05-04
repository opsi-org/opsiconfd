# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd - setup
"""

import grp
import os
import pwd
import resource
import string
from pathlib import Path

import psutil
from opsi.opsi.service.server import OpsiConfig
from opsi.process import ProcessError, run_command
from opsi.system.info import is_ucs
from rich import print as rich_print

from opsiconfd.config import OPSICONFD_HOME, config, get_server_role, opsi_config
from opsiconfd.logging import logger, secret_filter
from opsiconfd.utils import get_random_string, running_in_docker
from opsiconfd.utils.ucs import get_root_dn, get_ucs_admin_user


def create_user(username: str, primary_groupname: str, home: str, shell: str, system: bool = False) -> None:
	logger.notice("Creating user: %s", username)
	cmd = ["useradd", "-g", primary_groupname, "-d", home, "-s", shell]
	if system:
		cmd.append("--system")
	cmd.append(username)
	run_command(cmd, timeout=15)


def modify_user(username: str, home: str | None = None, shell: str | None = None) -> None:
	if not home and not shell:
		return
	logger.notice("Modifying user: %s (home=%s, shell=%s)", username, home, shell)
	cmd = ["usermod"]
	if home:
		cmd += ["-d", home]
	if shell:
		cmd += ["-s", shell]
	cmd.append(username)
	run_command(cmd, timeout=15)


def create_group(groupname: str, system: bool = False) -> None:
	logger.notice("Creating group: %s", groupname)
	cmd = ["groupadd"]
	if system:
		cmd.append("--system")
	cmd.append(groupname)
	logger.info("Running command: %s", cmd)
	run_command(cmd, timeout=15)


def add_user_to_group(username: str, groupname: str) -> None:
	logger.notice("Adding user '%s' to group '%s'", username, groupname)
	run_command(["usermod", "-a", "-G", groupname, username], timeout=15)


def set_primary_group(username: str, groupname: str) -> None:
	logger.notice("Setting primary group of user '%s' to '%s'", username, groupname)
	run_command(["usermod", "-g", groupname, username], timeout=15)


def setup_limits() -> None:
	logger.info("Setup system limits")
	# The hard limit is the maximum value that is allowed for the soft limit.
	# Any changes to the hard limit require root access.
	# The soft limit is the value that Linux uses to limit the system resources for running processes.
	rlimit_nofile = int(config.rlimit_nofile)
	(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
	logger.debug("Current RLIMIT_NOFILE (soft/hard): %d/%d", soft_limit, hard_limit)
	if soft_limit < rlimit_nofile or hard_limit < rlimit_nofile:
		try:
			hard_limit = max(hard_limit, rlimit_nofile)
			logger.info("Setting RLIMIT_NOFILE to (soft/hard): %d/%d", rlimit_nofile, hard_limit)
			resource.setrlimit(resource.RLIMIT_NOFILE, (rlimit_nofile, hard_limit))
			(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
		except Exception as err:
			logger.warning("Failed to set RLIMIT_NOFILE: %s", err)
	logger.info("Current RLIMIT_NOFILE (soft/hard): %d/%d", soft_limit, hard_limit)

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
		run_command(cmd, timeout=30)
	except ProcessError as err:
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
		run_command(cmd, timeout=30)
	except ProcessError as err:
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
		create_ucs_group(admingroup, "OPSI admin group", ucs_root_dn, ucs_admin_dn, ucs_password)
	try:
		grp.getgrnam(fileadmingroup)
	except KeyError:
		create_ucs_group(fileadmingroup, "OPSI fileadmin group", ucs_root_dn, ucs_admin_dn, ucs_password)
	try:
		grp.getgrnam(depot_user)
	except KeyError:
		create_ucs_user(depot_user, "OPSI depot user", "/var/lib/opsi", fileadmingroup, ucs_root_dn, None, ucs_admin_dn, ucs_password)
	try:
		grp.getgrnam(opsiconfd_user)
	except KeyError:
		create_ucs_user(
			opsiconfd_user, "OPSI configuration daemon user", OPSICONFD_HOME, fileadmingroup, ucs_root_dn, None, ucs_admin_dn, ucs_password
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

	opsi_config = OpsiConfig()
	try:
		grp.getgrnam(opsi_config.get("groups", "admingroup"))
	except KeyError:
		try:
			create_group(groupname=opsi_config.get("groups", "admingroup"), system=False)
		except Exception as err:
			logger.info(err)

	try:
		grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))
	except KeyError:
		try:
			create_group(groupname=opsi_config.get("groups", "fileadmingroup"), system=True)
		except Exception as err:
			logger.info(err)

	try:
		pwd.getpwnam(opsi_config.get("depot_user", "username"))
	except KeyError:
		try:
			create_user(
				username=opsi_config.get("depot_user", "username"),
				primary_groupname=opsi_config.get("groups", "fileadmingroup"),
				home=opsi_config.get("depot_user", "home"),
				shell="/bin/false",
				system=True,
			)
		except Exception as err:
			logger.info(err)

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
	run_command(["systemctl", "daemon-reload"])
	run_command(["systemctl", "enable", "opsiconfd.service"])


def set_unprivileged_port_start(port: int) -> None:
	conf = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	port_start = int(conf.read_text(encoding="ascii"))
	if port_start > port:
		logger.notice("Setting ip_unprivileged_port_start to %d", port)
		conf.write_text(str(port), encoding="ascii")
