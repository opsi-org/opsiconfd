# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.setup.samba
"""

import os
import re
from functools import lru_cache
from subprocess import CalledProcessError, run
import subprocess
from pathlib import Path

from configupdater import ConfigUpdater
from opsicommon.system.info import is_ucs

from opsiconfd.config import SMB_CONF, FQDN, opsi_config, config, str2bool
from opsiconfd.logging import logger, secret_filter
from opsiconfd.utils import get_ucs_user_details
from opsiconfd.utils.ucs import get_root_dn, get_ucs_admin_user


SHARES = {
	"opsi_depot": {
		"available": "yes",
		"comment": "opsi depot share (ro)",
		"path": "/var/lib/opsi/depot",
		"follow symlinks": "yes",
		"writeable": "no",
		"invalid users": "root",
		"acl allow execute always": "true",
	},
	"opsi_depot_rw": {
		"available": "yes",
		"comment": "opsi depot share (rw)",
		"path": "/var/lib/opsi/depot",
		"follow symlinks": "yes",
		"writeable": "yes",
		"invalid users": "root",
		"create mask": "0660",
		"directory mask": "0770",
		"acl allow execute always": "true",
	},
	"opsi_images": {
		"available": "yes",
		"comment": "opsi ntfs images share (rw)",
		"path": "/var/lib/opsi/ntfs-images",
		"writeable": "yes",
		"invalid users": "root",
		"create mask": "0660",
		"directory mask": "0770",
	},
	"opsi_workbench": {
		"available": "yes",
		"comment": "opsi workbench",
		"path": "/var/lib/opsi/workbench",
		"writeable": "yes",
		"invalid users": f"root {opsi_config.get('depot_user', 'username')}",
		"create mask": "0660",
		"directory mask": "0770",
		"acl allow execute always": "true",
	},
	"opsi_repository": {
		"available": "yes",
		"comment": "opsi repository share (ro)",
		"path": "/var/lib/opsi/repository",
		"follow symlinks": "yes",
		"writeable": "no",
		"invalid users": f"root {opsi_config.get('depot_user', 'username')}",
	},
	"opsi_logs": {
		"available": "yes",
		"comment": "opsi logs share (ro)",
		"path": "/var/log/opsi",
		"follow symlinks": "yes",
		"writeable": "no",
		"invalid users": f"root {opsi_config.get('depot_user', 'username')}",
	},
}


@lru_cache
def is_samba3() -> bool:
	try:
		return (
			run(["smbd", "-V"], shell=False, text=True, encoding="utf-8", check=False, capture_output=True)
			.stdout.strip()
			.lower()
			.startswith("version 3")
		)
	except FileNotFoundError:
		return False


@lru_cache
def get_smbd_service_name() -> str:
	try:
		possible_names = ("samba", "smb", "smbd")
		pattern = re.compile(r"^\s*([a-z]+)\@?\.service")
		for line in run(
			["systemctl", "list-unit-files"], shell=False, text=True, encoding="utf-8", check=True, capture_output=True
		).stdout.split("\n"):
			match = pattern.match(line)
			if match and match.group(1) in possible_names:
				return match.group(1)
	except (FileNotFoundError, PermissionError, CalledProcessError) as err:
		logger.info("Failed to get samba service name: %s", err)

	return "smbd"


def reload_samba() -> None:
	service_name = get_smbd_service_name()
	logger.notice("Reloading Samba service %s", service_name)
	try:
		run(["systemctl", "reload", service_name], shell=False, text=True, encoding="utf-8", check=True, capture_output=True)
	except CalledProcessError as err:
		logger.warning("%s %s %s", err, err.stdout, err.stderr)
	except FileNotFoundError as err:
		logger.warning("Failed to reload samba service %r: %s", service_name, err)


def setup_samba(interactive: bool = False) -> None:
	logger.info("Setup samba")
	if is_ucs():
		logger.info("UCS detected")
		ucs_admin_dn, ucs_password = get_ucs_admin_user(interactive)

		samba_reload_needed = False
		for share_name, share_options in SHARES.items():
			changed = setup_ucs_samba_share(
				name=share_name,
				path=share_options["path"],
				writable=str2bool(share_options.get("writeable", "no")),
				invalid_users=share_options.get("invalid users"),
				follow_symlinks=str2bool(share_options.get("follow symlinks", "no")),
				create_mask=share_options.get("create mask"),
				directory_mask=share_options.get("directory mask"),
				ucs_admin_dn=ucs_admin_dn,
				ucs_password=ucs_password,
			)
			if changed:
				samba_reload_needed = True
		if samba_reload_needed:
			logger.info("Samba config changed, reloading")
			reload_samba()
		return
	if not os.path.exists(SMB_CONF):
		return

	samba_config = ConfigUpdater(delimiters=("=",))
	samba_config.read(SMB_CONF)

	indent = "   "
	changed = False
	for share_name, share_options in SHARES.items():
		if not samba_config.has_section(share_name):
			changed = True
			last_section = samba_config[samba_config.sections()[-1]]
			last_section.add_after.space(1).section(share_name)

		for option, value in share_options.items():
			if option == "acl allow execute always" and is_samba3():
				continue
			if not samba_config.has_option(share_name, option):
				changed = True
				samba_config.set(share_name, f"{indent}{option}", value)

	if changed:
		logger.info("Samba config changed, reloading")
		samba_config.update_file()
		reload_samba()


def setup_ucs_samba_share(
	*,
	name: str,
	path: str,
	writable: bool = False,
	invalid_users: str | None = None,
	follow_symlinks: bool = False,
	create_mask: str | None = None,
	directory_mask: str | None = None,
	ucs_admin_dn: str | None = None,
	ucs_password: str | None = None,
) -> bool:
	if ucs_password:
		secret_filter.add_secrets(ucs_password)
	if not is_ucs():
		logger.debug("Not a UCS system, skipping ucs share creation")
		return False

	changed = False
	share_config_path = Path("/etc/samba/shares.conf.d", name)
	if share_config_path.exists():
		for option, value in SHARES.get(name, {}).items():
			if option in ("available", "acl allow execute always", "comment"):
				logger.debug("Skipping option %s. This option is not set in ucs samba.", option)
				continue
			option = option.replace("mask", "mode")
			share_config = ConfigUpdater(delimiters=("=",))
			share_config.read(share_config_path)
			if not share_config.has_option(name, option) or share_config.get(name, option).value != value:
				changed = True

	if not changed:
		logger.info("No changes for UCS samba share %s", name)
		return False

	logger.info("Creating UCS Samba share %s", name)

	ucs_root_dn = get_root_dn()
	user_info = get_ucs_user_details(config.run_as_user)
	if not user_info:
		logger.error("Failed to get user information for %s", config.run_as_user)
		return False
	user_id = user_info.uid
	group_id = user_info.gid

	logger.debug("Creating container for samba shares")

	# create container for samba shares if it does not exist
	cmd = [
		"udm",
		"container/cn",
		"create",
		"--ignore_exists",
		"--position",
		f"cn=shares,{ucs_root_dn}",
		"--set",
		f"name={FQDN}",
	]

	if ucs_admin_dn and ucs_password:
		cmd.append("--binddn")
		cmd.append(ucs_admin_dn)
		cmd.append("--bindpwd")
		cmd.append(ucs_password)
	logger.debug(subprocess.list2cmdline(cmd))
	try:
		subprocess.check_output(cmd, timeout=10)
	except subprocess.CalledProcessError as err:
		logger.error("Failed to create container for samba shares: %s", err)

	# remove existing share
	cmd = ["udm", "shares/share", "remove", "--filter", f"name={name}", "--ignore_not_exists"]
	if ucs_admin_dn and ucs_password:
		cmd.append("--binddn")
		cmd.append(ucs_admin_dn)
		cmd.append("--bindpwd")
		cmd.append(ucs_password)
	logger.debug(subprocess.list2cmdline(cmd))
	try:
		subprocess.check_output(cmd, timeout=10)
	except subprocess.CalledProcessError as err:
		logger.error("Failed to remove samba share %r: %s", name, err)

	# create samba share
	cmd = [
		"udm",
		"shares/share",
		"create",
		"--ignore_exists",
		"--position",
		f"cn={FQDN},cn=shares,{ucs_root_dn}",
		"--set",
		f"name={name}",
		"--set",
		f"host={FQDN}",
		"--set",
		f"path={path}",
		"--set",
		f"owner={user_id}",
		"--set",
		f"group={group_id}",
		"--set",
		f"sambaName={name}",
		"--set",
		f'sambaInvalidUsers={invalid_users or ""}',
		"--set",
		"sambaBrowseable=1",
		"--set",
		"sambaPublic=0",
	]
	if writable:
		cmd.append("--set")
		cmd.append("sambaWriteable=1")
	else:
		cmd.append("--set")
		cmd.append("sambaWriteable=0")
	if follow_symlinks:
		cmd.append("--set")
		cmd.append(
			"sambaCustomSettings=" + '"follow symlinks" yes',
		)
	if create_mask:
		cmd.append("--set")
		cmd.append(f"sambaCreateMode={create_mask}")
	if directory_mask:
		cmd.append("--set")
		cmd.append(f"sambaDirectoryMode={directory_mask}")
	if ucs_admin_dn and ucs_password:
		cmd.append("--binddn")
		cmd.append(ucs_admin_dn)
		cmd.append("--bindpwd")
		cmd.append(ucs_password)

	logger.debug(subprocess.list2cmdline(cmd))
	try:
		subprocess.check_output(cmd, timeout=10)
	except subprocess.CalledProcessError as err:
		logger.error("Failed to create samba share %r: %s", name, err)

	return True
