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
	backend = None
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
		backend,
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
		self.backend = backend
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
			"role": f"user.role.{{{self.name}}}.has_role",
			"modified": f"user.role.{{{self.name}}}.modified",
			"read_only": f"user.role.{{{self.name}}}.privilege.host.all.registered_readonly",
			"create_client": f"user.role.{{{self.name}}}.privilege.host.createclient",
			"opsi_server_write": f"user.role.{{{self.name}}}.privilege.host.opsiserver.write",
			"ssh_command_management": f"user.role.{{{self.name}}}.ssh.commandmanagement.active",
			"ssh_command": f"user.role.{{{self.name}}}.ssh.commands.active",
			"ssh_menu_server_console": f"user.role.{{{self.name}}}.ssh.menu_serverconsole.active",
			"ssh_server_configuration": f"user.role.{{{self.name}}}.ssh.serverconfiguration.active",
			"depot_access_configured": f"user.role.{{{self.name}}}.privilege.host.depotaccess.configured",
			"depot_access": f"user.role.{{{self.name}}}.privilege.host.depotaccess.depots",
			"host_group_access_configured": f"user.role.{{{self.name}}}.privilege.host.groupaccess.configured",
			"host_group_access": f"user.role.{{{self.name}}}.privilege.host.groupaccess.hostgroups",
			"product_group_access_configured": f"user.role.{{{self.name}}}.privilege.product.groupaccess.configured",
			"product_group_access": f"user.role.{{{self.name}}}.privilege.product.groupaccess.productgroups",
		}

		self.create_configes()

	def create_configes(self) -> None:
		for value_key, config in self.configes.items():
			current_conf = self.backend.config_getObjects(configId=config)
			if current_conf:
				self.__setattr__(value_key, current_conf[0].defaultValues)
			if value_key == self.role:
				self.backend.config_createObjects([Config(config, defaultValues=[self.role.name])])
			elif isinstance(self.__getattribute__(value_key), list):
				self.backend.config_createObjects([Config(config, defaultValues=self.__getattribute__(value_key))])
			else:
				self.backend.config_createObjects([Config(config, defaultValues=[self.__getattribute__(value_key)])])


def create_user(backend, name: str, groups: set) -> None:
	logger.devel(backend.config_getObjects(configId="user.{}.register")[0])
	if not backend.config_getObjects(configId="user.{}.register")[0].defaultValues[0]:
		return

	user_group = "default"
	for group in groups:
		user_roles = backend.config_getObjects(configId="opsi.roles")[0].defaultValues
		if group in user_roles:
			user_group = group
			break
	role = Role(backend, user_group)
	User(backend=backend, name=name, role=role)
