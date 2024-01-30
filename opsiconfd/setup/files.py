# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - setup
"""

import os
import shutil
import time
from pathlib import Path

from opsicommon.server.rights import (  # type: ignore[import]
	DirPermission,
	FilePermission,
	PermissionRegistry,
	set_rights,
)

from opsiconfd.config import (
	AUDIT_HARDWARE_CONFIG_LOCALES_DIR,
	DEPOT_DIR,
	FILE_TRANSFER_STORAGE_DIR,
	LOG_DIR,
	NTFS_IMAGES_DIR,
	OPSI_LICENSE_DIR,
	OPSICONFD_DIR,
	OPSICONFD_HOME,
	PUBLIC_DIR,
	REPOSITORY_DIR,
	TMP_DIR,
	VAR_ADDON_DIR,
	WORKBENCH_DIR,
	config,
	opsi_config,
)
from opsiconfd.dhcpd import get_dhcpd_conf_location
from opsiconfd.logging import logger
from opsiconfd.utils import get_file_md5sum
from opsiconfd.ssl import setup_ssl_file_permissions
from opsiconfd.backend.auth import write_default_acl_conf

EXTENDER_FILES = (
	"10_opsi.conf",
	"10_wim.conf",
	"20_easy.conf",
	"20_legacy.conf",
	"30_kiosk.conf",
	"30_sshcommands.conf",
	"40_admin_tasks.conf",
	"40_groupActions.conf",
	"45_deprecated.conf",
	"70_dynamic_depot.conf",
	"70_wan.conf",
)


def _get_default_dirs() -> list[str]:
	dirs = [
		f"/{LOG_DIR}/bootimage",
		f"/{LOG_DIR}/clientconnect",
		f"/{LOG_DIR}/instlog",
		f"/{LOG_DIR}/userlogin",
		TMP_DIR,
		DEPOT_DIR,
		NTFS_IMAGES_DIR,
		REPOSITORY_DIR,
		PUBLIC_DIR,
		WORKBENCH_DIR,
		VAR_ADDON_DIR,
		OPSI_LICENSE_DIR,
		OPSICONFD_HOME,
		FILE_TRANSFER_STORAGE_DIR,
	]
	if config.log_file:
		dirs.append(os.path.dirname(config.log_file))
	return dirs


def move_exender_files() -> None:
	extender_folder = Path("/etc/opsi/backendManager/extend.d")
	if not extender_folder.exists():
		return
	if not any(extender_folder.iterdir()):
		logger.notice("Removing empty folder '%s'", extender_folder)
		extender_folder.rmdir()
		return
	backup_folder = extender_folder.with_suffix(".old")
	if not backup_folder.exists():
		backup_folder.mkdir()
	for extender_file in EXTENDER_FILES:
		file_path = extender_folder.joinpath(extender_file)
		if file_path.exists():
			logger.notice("Moving '%s' to '%s'", extender_file, backup_folder)
			shutil.move(file_path, backup_folder.joinpath(extender_file))
	permission = DirPermission(backup_folder, config.run_as_user, opsi_config.get("groups", "admingroup"), 0o660, 0o770)
	PermissionRegistry().register_permission(permission)
	set_rights(permission.path)


def cleanup_audit_hardware_config_locales_dir() -> None:
	for file in Path(AUDIT_HARDWARE_CONFIG_LOCALES_DIR).iterdir():
		if file.suffix != ".properties" and file.is_file():
			logger.notice("Removing legacy locale file '%s'", file)
			file.unlink()


def migrate_acl_conf_if_default() -> None:
	"""
	If acl.conf is the default 4.1 configuration,
	replace it with the 4.3 (and 4.2) default.
	"""
	md5sum = get_file_md5sum(config.acl_file)
	if md5sum in ("74a0dbc5320fa0a80f8f6edb0d43a7e7",):  # 4.1 default
		write_default_acl_conf(Path(config.acl_file))


def setup_files() -> None:
	for _dir in _get_default_dirs():
		if _dir and not os.path.isdir(_dir) and not os.path.islink(_dir):
			os.makedirs(_dir)
			set_rights(_dir)
	move_exender_files()
	cleanup_audit_hardware_config_locales_dir()
	migrate_acl_conf_if_default()


def setup_file_permissions() -> None:
	logger.info("Setup file permissions")

	permissions = [
		FilePermission("/etc/shadow", None, "shadow", 0o640),
		FilePermission(
			f"{os.path.dirname(config.log_file)}/opsiconfd.log", config.run_as_user, opsi_config.get("groups", "admingroup"), 0o660
		),
		DirPermission(OPSICONFD_DIR, config.run_as_user, opsi_config.get("groups", "admingroup"), 0o660, 0o770, recursive=False),
		DirPermission(OPSICONFD_HOME, config.run_as_user, opsi_config.get("groups", "admingroup"), 0o600, 0o700, recursive=False),
		DirPermission(VAR_ADDON_DIR, config.run_as_user, opsi_config.get("groups", "fileadmingroup"), 0o660, 0o770),
	]

	# On many systems dhcpd is running as unprivileged user (i.e. dhcpd)
	# This user needs read permission
	dhcpd_config_file = get_dhcpd_conf_location()
	permissions.append(FilePermission(str(dhcpd_config_file), config.run_as_user, opsi_config.get("groups", "admingroup"), 0o664))
	dhcpd_config_dir = dhcpd_config_file.parent
	if len(dhcpd_config_dir.parts) >= 3:
		permissions.append(DirPermission(str(dhcpd_config_dir), None, None, 0o664, 0o775, recursive=False))

	PermissionRegistry().register_permission(*permissions)
	for permission in permissions:
		set_rights(permission.path)

	set_rights("/etc/opsi")
	setup_ssl_file_permissions()

	for path_str in _get_default_dirs():
		path = Path(path_str)
		if not path.is_dir():
			continue
		try:
			owner = path.owner()
		except KeyError as err:
			logger.warning("Failed to get owner of '%s': %s", path, err)
			owner = ""
		if owner != config.run_as_user:
			try:
				set_rights(str(path))
			except KeyError as err:
				logger.warning("Failed to set permissions on '%s': %s", str(path), err)


def cleanup_log_files() -> None:
	logger.info("Cleanup log files")
	now = time.time()
	min_mtime = now - 3600 * 24 * 30  # 30 days
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
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err)

	for link in links:
		try:
			dst = os.path.realpath(link)
			if not os.path.exists(dst):
				os.unlink(link)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err)
