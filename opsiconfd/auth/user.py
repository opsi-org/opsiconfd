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
			self.role = Role(self.backend)

		now = datetime.utcnow()
		self.modified = now.strftime("%Y-%m-%d %H:%M:%S")

		self.configes = {
			"role": f"user.{{{self.name}}}.has_role",
			"modified": f"user.{{{self.name}}}.modified",
			"read_only": f"user.{{{self.name}}}.privilege.host.all.registered_readonly",
			"create_client": f"user.{{{self.name}}}.privilege.host.createclient",
			"opsi_server_write": f"user.{{{self.name}}}.privilege.host.opsiserver.write",
			"ssh_command_management": f"user.{{{self.name}}}.ssh.commandmanagement.active",
			"ssh_command": f"user.{{{self.name}}}.ssh.commands.active",
			"ssh_menu_server_console": f"user.{{{self.name}}}.ssh.menu_serverconsole.active",
			"ssh_server_configuration": f"user.{{{self.name}}}.ssh.serverconfiguration.active",
			"depot_access_configured": f"user.{{{self.name}}}.privilege.host.depotaccess.configured",
			"depot_access": f"user.{{{self.name}}}.privilege.host.depotaccess.depots",
			"host_group_access_configured": f"user.{{{self.name}}}.privilege.host.groupaccess.configured",
			"host_group_access": f"user.{{{self.name}}}.privilege.host.groupaccess.hostgroups",
			"product_group_access_configured": f"user.{{{self.name}}}.privilege.product.groupaccess.configured",
			"product_group_access": f"user.{{{self.name}}}.privilege.product.groupaccess.productgroups",
		}

		self.create_configes()

	def create_configes(self) -> None:
		from opsiconfd.backend import (
			get_unprotected_backend,  # pylint: disable=import-outside-toplevel
		)

		backend = get_unprotected_backend()

		for value_key, config in self.configes.items():
			current_conf = backend.config_getObjects(configId=config)
			if current_conf and value_key != "role":
				self.__setattr__(value_key, current_conf[0].defaultValues)
			if value_key == "role":
				backend.config_createObjects([Config(config, defaultValues=[self.role.name])])
			elif isinstance(self.__getattribute__(value_key), list):
				backend.config_createObjects([Config(config, defaultValues=self.__getattribute__(value_key))])
			else:
				backend.config_createObjects([Config(config, defaultValues=[self.__getattribute__(value_key)])])


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
	role = Role(backend, user_group)
	User(name=name, role=role)
