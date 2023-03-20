# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.setup.samba
"""

import os
import re
import string
from functools import lru_cache
from subprocess import CalledProcessError, run

from configupdater import ConfigUpdater

from opsiconfd.config import SMB_CONF, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import get_random_string

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
		"acl allow execute always": "true",
	},
	"opsi_images": {
		"available": "yes",
		"comment": "opsi ntfs images share (rw)",
		"path": "/var/lib/opsi/ntfs-images",
		"writeable": "yes",
		"invalid users": "root",
	},
	"opsi_workbench": {
		"available": "yes",
		"comment": "opsi workbench",
		"path": "/var/lib/opsi/workbench",
		"writeable": "yes",
		"invalid users": "root",
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
		"invalid users": "root",
	},
	"opsi_logs": {
		"available": "yes",
		"comment": "opsi logs share (ro)",
		"path": "/var/log/opsi",
		"follow symlinks": "yes",
		"writeable": "no",
		"invalid users": "root",
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
	logger.notice(f"Reloading Samba service {service_name}")
	try:
		run(["systemctl", "reload", service_name], shell=False, text=True, encoding="utf-8", check=True, capture_output=True)
	except CalledProcessError as err:
		logger.warning("%s %s %s", err, err.stdout, err.stderr)
	except FileNotFoundError as err:
		logger.warning(err)


def setup_samba() -> None:
	logger.info("Setup samba")
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

	# pylint: disable=import-outside-toplevel
	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()
	username = opsi_config.get("depot_user", "username")
	try:
		backend.user_getCredentials(username)
	except Exception:  # pylint: disable=broad-except
		backend.user_setCredentials(
			username, get_random_string(32, alphabet=string.ascii_letters + string.digits, mandatory_alphabet="/^@?-")
		)
