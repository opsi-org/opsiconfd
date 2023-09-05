# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.auth.user
"""

from datetime import datetime
from opsicommon.objects import Config
from opsiconfd.auth.role import Role


from opsiconfd.logging import logger


class User:
	name: str
	role: Role
	read_only: bool = False
	create_client: bool = True
	opsi_server_write: bool = True
	depot_access_configured: bool = False
	depot_access: list[str] | None = None
	host_group_access_configured: bool = False
	host_group_access: list[str] | None = None
	product_group_access_configured: bool = False
	product_group_access: list[str] | None = None
	ssh_command_management: bool = False
	ssh_command: bool = True
	ssh_menu_server_console: bool = True
	ssh_server_configuration: bool = True

	def __init__(
		self,
		name: str,
		role: Role | None = None,
		read_only: bool = False,
		create_client: bool = True,
		opsi_server_write: bool = True,
		depot_access: list[str] | None = None,
		host_group_access: list[str] | None = None,
		product_group_access: list[str] | None = None,
		ssh_command_management: bool = False,
		ssh_command: bool = True,
		ssh_menu_server_console: bool = True,
		ssh_server_configuration: bool = True,
	):
		self.name = name
		self.read_only = read_only
		self.create_client = create_client
		self.opsi_server_write = opsi_server_write
		self.depot_access = depot_access
		self.host_group_access = host_group_access
		self.product_group_access = product_group_access
		self.ssh_command_management = ssh_command_management
		self.ssh_command = ssh_command
		self.ssh_menu_server_console = ssh_menu_server_console
		self.ssh_server_configuration = ssh_server_configuration

		if role:
			self.role = role
		else:
			self.role = Role()

		now = datetime.utcnow()
		self.modified = now.strftime("%Y-%m-%d %H:%M:%S")

		self.configes = {
			"role": {"configId": f"user.{{{self.name}}}.has_role", "type": "UnicodeConfig", "multiValue": False},
			"modified": {"configId": f"user.{{{self.name}}}.modified", "type": "UnicodeConfig", "multiValue": False},
			"read_only": {"configId": f"user.{{{self.name}}}.privilege.host.all.registered_readonly", "type": "BoolConfig"},
			"create_client": {"configId": f"user.{{{self.name}}}.privilege.host.createclient", "type": "BoolConfig"},
			"opsi_server_write": {"configId": f"user.{{{self.name}}}.privilege.host.opsiserver.write", "type": "BoolConfig"},
			"ssh_command_management": {"configId": f"user.{{{self.name}}}.ssh.commandmanagement.active", "type": "BoolConfig"},
			"ssh_command": {"configId": f"user.{{{self.name}}}.ssh.commands.active", "type": "BoolConfig"},
			"ssh_menu_server_console": {"configId": f"user.{{{self.name}}}.ssh.menu_serverconsole.active", "type": "BoolConfig"},
			"ssh_server_configuration": {"configId": f"user.{{{self.name}}}.ssh.serverconfiguration.active", "type": "BoolConfig"},
			"depot_access_configured": {
				"configId": f"user.{{{self.name}}}.privilege.host.depotaccess.configured",
				"type": "BoolConfig",
			},
			"depot_access": {
				"configId": f"user.{{{self.name}}}.privilege.host.depotaccess.depots",
				"type": "UnicodeConfig",
				"multiValue": True,
			},
			"host_group_access_configured": {
				"configId": f"user.{{{self.name}}}.privilege.host.groupaccess.configured",
				"type": "BoolConfig",
			},
			"host_group_access": {
				"configId": f"user.{{{self.name}}}.privilege.host.groupaccess.hostgroups",
				"type": "UnicodeConfig",
				"multiValue": True,
			},
			"product_group_access_configured": {
				"configId": f"user.{{{self.name}}}.privilege.product.groupaccess.configured",
				"type": "BoolConfig",
			},
			"product_group_access": {
				"configId": f"user.{{{self.name}}}.privilege.product.groupaccess.productgroups",
				"type": "UnicodeConfig",
				"multiValue": True,
			},
		}

		self.create_configes()

	def create_configes(self) -> None:
		from opsiconfd.backend import (
			get_unprotected_backend,  # pylint: disable=import-outside-toplevel
		)

		backend = get_unprotected_backend()

		for value_key, config in self.configes.items():
			current_conf = backend.config_getObjects(configId=config)
			if current_conf:
				self.__setattr__(value_key, current_conf[0].defaultValues)
			if config["type"] == "UnicodeConfig" and config["multiValue"]:
				backend.config_createUnicode(
					id=config["configId"], defaultValues=self.__getattribute__(value_key), multiValue=config["multiValue"]
				)
			elif value_key == "role":
				backend.config_createUnicode(id=config["configId"], defaultValues=[self.role.name])
			elif config["type"] == "UnicodeConfig":
				backend.config_createUnicode(id=config["configId"], defaultValues=[self.__getattribute__(value_key)])
			else:
				backend.config_createBool(id=config["configId"], defaultValues=[self.__getattribute__(value_key)])


def create_user(name: str, groups: set) -> None:
	from opsiconfd.backend import (
		get_unprotected_backend,  # pylint: disable=import-outside-toplevel
	)

	backend = get_unprotected_backend()

	logger.devel(backend.config_getObjects(configId="user.{}.register")[0])
	if not backend.config_getObjects(configId="user.{}.register")[0].defaultValues[0]:
		return

	user_group = "default"
	for group in groups:
		user_roles = backend.config_getObjects(configId="opsi.roles")
		if user_roles and group in user_roles[0].defaultValues:
			user_group = group
			break
	role = Role(user_group)
	User(name=name, role=role)
