# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backup
"""

from datetime import datetime
from pathlib import Path
from typing import Any

from opsiconfd import __version__
from opsiconfd.backend import get_unprotected_backend
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.mysql.schema import (
	create_database,
	drop_database,
	update_database,
)
from opsiconfd.config import (
	FQDN,
	OPSI_LICENSE_PATH,
	OPSI_MODULES_PATH,
	OPSI_PASSWD_FILE,
	SSH_COMMANDS_CUSTOM_FILE,
	SSH_COMMANDS_DEFAULT_FILE,
	config,
	opsi_config,
)
from opsiconfd.logging import logger

OBJECT_CLASSES = (
	"Host",
	"Config",
	"Product",
	"ProductProperty",
	"ProductDependency",
	"ProductOnDepot",
	"ProductOnClient",
	"ProductPropertyState",
	"Group",
	"ObjectToGroup",
	"AuditSoftware",
	"AuditSoftwareOnClient",
	"AuditHardware",
	"AuditHardwareOnHost",
	"LicenseContract",
	"SoftwareLicense",
	"LicensePool",
	"AuditSoftwareToLicensePool",
	"SoftwareLicenseToLicensePool",
	"LicenseOnClient",
)


def get_config_files() -> dict[str, Path]:
	backend_config_dir = Path(config.backend_config_dir)
	config_files = {
		"opsiconfd_conf": Path(config.config_file),
		"opsi_conf": Path(opsi_config.config_file),
		"opsi_passwd": Path(OPSI_PASSWD_FILE),
		"ssl_ca_key": Path(config.ssl_ca_key),
		"ssl_ca_cert": Path(config.ssl_ca_cert),
		"ssl_server_key": Path(config.ssl_server_key),
		"ssl_server_cert": Path(config.ssl_server_cert),
		"ssh_commands_custom": Path(SSH_COMMANDS_CUSTOM_FILE),
		"ssh_commands_default": Path(SSH_COMMANDS_DEFAULT_FILE),
		"dhcpd_conf": backend_config_dir / "dhcpd.conf",
		"hostcontrol_conf": backend_config_dir / "hostcontrol.conf",
		"jsonrpc_conf": backend_config_dir / "jsonrpc.conf",
		"mysql_conf": backend_config_dir / "mysql.conf",
		"opsipxeconfd_conf": backend_config_dir / "opsipxeconfd.conf",
		"acl_conf": backend_config_dir / "acl.conf",
	}
	extension_config_dir = Path(config.extension_config_dir)
	for extension_config_file in extension_config_dir.glob("*.conf"):  # pylint: disable=use-dict-comprehension
		config_files[f"extension_conf_{extension_config_file.with_suffix('').name}"] = extension_config_file

	modules_file = Path(OPSI_MODULES_PATH)
	if modules_file.exists():
		config_files["modules"] = modules_file

	license_dir = Path(OPSI_LICENSE_PATH)
	for license_file in license_dir.glob("*.opsilic"):  # pylint: disable=use-dict-comprehension
		config_files[f"opsilic_{license_file.with_suffix('').name}"] = license_file

	return config_files


def create_backup(config_files: bool = True) -> dict[str, dict[str, Any]]:
	now = datetime.utcnow()
	data: dict[str, dict[str, Any]] = {
		"meta": {
			"type": "opsiconfd_backup",
			"version": "1",
			"opsiconfd_version": __version__,
			"timestamp": now.timestamp(),
			"datetime": now.strftime("%Y-%m-%d %H:%M:%S"),
			"node_name": config.node_name,
			"fqdn": FQDN,
			"host_id": str(opsi_config.get("host", "id")),
			"server_role": str(opsi_config.get("host", "server-role")),
		},
		"objects": {},
		"config_files": {},
	}

	backend = get_unprotected_backend()
	for obj_class in OBJECT_CLASSES:  # pylint: disable=loop-global-usage
		method = getattr(backend, f"{obj_class[0].lower()}{obj_class[1:]}_getObjects")
		data["objects"][obj_class] = [o.to_hash() for o in method()]  # pylint: disable=loop-invariant-statement

	if config_files:
		for name, file in get_config_files().items():
			content = None
			if file.exists():
				content = file.read_text(encoding="utf-8")
			else:
				logger.warning("Config file '%s' not found, skipping in backup", file)
			data["config_files"][name] = {"path": str(file.absolute()), "content": content}  # pylint: disable=loop-invariant-statement
	return data


def restore_backup(data: dict[str, dict[str, Any]], config_files: bool = True) -> None:
	if data.get("meta", {}).get("type") != "opsiconfd_backup":
		raise ValueError("Invalid backup")
	version = data["meta"].get("version")
	if version != "1":
		raise ValueError(f"Invalid backup version: {version!r}")

	if config_files and data.get("config_files"):
		for name, file in get_config_files().items():
			backup_file = data["config_files"].get(name)
			if backup_file and backup_file["content"] is not None:
				file.write_text(backup_file["content"], encoding="utf-8")

	mysql = MySQLConnection()
	mysql.connect()
	drop_database(mysql)
	create_database(mysql)
	mysql.disconnect()
	mysql.connect()
	update_database(mysql)

	backend = get_unprotected_backend()
	num_objects = sum(len(objs) for objs in data["objects"].values())
	object_num = 0
	for obj_class in OBJECT_CLASSES:  # pylint: disable=loop-global-usage
		objects = data["objects"].get(obj_class)
		if not objects:
			continue

		# method = getattr(backend, f"{obj_class[0].lower()}{obj_class[1:]}_createObjects")
		# method(objects)

		method = getattr(backend, f"{obj_class[0].lower()}{obj_class[1:]}_insertObject")
		for obj in objects:
			object_num += 1
			# print(f"{object_num}/{num_objects}")
			logger.trace("Insert %s object: %s", obj_class, obj)
			try:  # pylint: disable=loop-try-except-usage
				method(obj)
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err)
