# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - setup
"""

import os
import time
from pathlib import Path

from OPSI.System.Posix import locateDHCPDConfig  # type: ignore[import]
from opsicommon.server.rights import (  # type: ignore[import]
	DirPermission,
	FilePermission,
	PermissionRegistry,
	set_rights,
)

from opsiconfd.config import (
	DEPOT_DIR,
	FILE_TRANSFER_STORAGE_DIR,
	LOG_DIR,
	NTFS_IMAGES_DIR,
	OPSI_LICENSE_DIR,
	OPSICONFD_HOME,
	PUBLIC_DIR,
	REPOSITORY_DIR,
	TMP_DIR,
	VAR_ADDON_DIR,
	WORKBENCH_DIR,
	config,
	opsi_config,
)
from opsiconfd.logging import logger
from opsiconfd.ssl import setup_ssl_file_permissions


def _get_default_dirs() -> list[str]:
	return [
		f"/{LOG_DIR}/bootimage",
		f"/{LOG_DIR}/clientconnect",
		f"/{LOG_DIR}/instlog",
		f"/{LOG_DIR}/userlogin",
		os.path.dirname(config.log_file),
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


def setup_files() -> None:
	for _dir in _get_default_dirs():
		if not os.path.isdir(_dir) and not os.path.islink(_dir):
			os.makedirs(_dir)
			set_rights(_dir)


def setup_file_permissions() -> None:
	logger.info("Setup file permissions")

	dhcpd_config_file = locateDHCPDConfig("/etc/dhcp3/dhcpd.conf")
	permissions = (
		FilePermission("/etc/shadow", None, "shadow", 0o640),
		FilePermission(
			f"{os.path.dirname(config.log_file)}/opsiconfd.log", config.run_as_user, opsi_config.get("groups", "admingroup"), 0o660
		),
		# On many systems dhcpd is running as unprivileged user (i.e. dhcpd)
		# This user needs read permission
		FilePermission(dhcpd_config_file, config.run_as_user, opsi_config.get("groups", "admingroup"), 0o664),
		DirPermission(OPSICONFD_HOME, config.run_as_user, opsi_config.get("groups", "admingroup"), 0o660, 0o770),
		DirPermission(VAR_ADDON_DIR, config.run_as_user, opsi_config.get("groups", "fileadmingroup"), 0o660, 0o770),
	)
	PermissionRegistry().register_permission(*permissions)
	for permission in permissions:
		set_rights(permission.path)

	set_rights("/etc/opsi")
	setup_ssl_file_permissions()

	for path_str in _get_default_dirs():
		try:
			path = Path(path_str)
			if path.is_dir() and path.owner() != config.run_as_user:
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
