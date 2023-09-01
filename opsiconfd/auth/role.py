# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.auth.role
"""

from datetime import datetime
from opsicommon.objects import Config

from opsiconfd.logging import logger

# DEFAULT_ROLE = [
# 	Config("user.{default}.has_role"),
# 	Config("user.role.{default}.privilege.host.all.registered_readonly", defaultValues=[False]),
# 	Config("user.role.{default}.privilege.host.createclient", defaultValues=[True]),
# 	Config("user.role.{default}.privilege.host.depotaccess.configured", defaultValues=[False]),
# 	Config("user.role.{default}.privilege.host.depotaccess.depots", defaultValues=[]),
# 	Config("user.role.{default}.privilege.host.groupaccess.configured", defaultValues=[False]),
# 	Config("user.role.{default}.privilege.host.groupaccess.hostgroups", defaultValues=[]),
# 	Config("user.role.{default}.privilege.host.opsiserver.write", defaultValues=[True]),
# 	Config("user.role.{default}.privilege.product.groupaccess.configured", defaultValues=[False]),
# 	Config("user.role.{default}.privilege.product.groupaccess.productgroups", defaultValues=[]),
# 	Config("user.role.{default}.ssh.commandmanagement.active", defaultValues=[False]),
# 	Config("user.role.{default}.ssh.commands.active", defaultValues=[True]),
# 	Config("user.role.{default}.ssh.menu_serverconsole.active", defaultValues=[True]),
# 	Config("user.role.{default}.ssh.serverconfiguration.active", defaultValues=[True]),
# ]


class Role:
	name: str = "default"
	role: str = ""
	modified: str = ""
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
	configes: dict[str, str] = {}

	def __init__(
		self,
		backend,
		name: str = "default",
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

		# if self.depot_access:
		# 	self.configes.append()

		# else:
		# 	self.configes.append(Config(f"user.role.{{{self.name}}}.privilege.host.depotaccess.configured", defaultValues=[False]))
		# 	self.configes.append(Config(f"user.role.{{{self.name}}}.privilege.host.depotaccess.depots", defaultValues=[]))

		# if self.host_group_access:
		# 	self.configes.append(
		# 		Config(f"user.role.{{{self.name}}}.privilege.host.groupaccess.configured", defaultValues=[self.host_group_access])
		# 	)
		# 	self.configes.append(
		# 		Config(f"user.role.{{{self.name}}}.privilege.host.groupaccess.hostgroups", defaultValues=[self.host_group_access])
		# 	)
		# else:
		# 	self.configes.append(Config(f"user.role.{{{self.name}}}.privilege.host.groupaccess.configured", defaultValues=[False]))
		# 	self.configes.append(Config(f"user.role.{{{self.name}}}.privilege.host.groupaccess.hostgroups", defaultValues=[]))

		# if self.product_group_access:
		# 	self.configes.append(
		# 		Config(f"user.role.{{{self.name}}}.privilege.product.groupaccess.configured", defaultValues=[self.product_group_access])
		# 	)
		# 	self.configes.append(
		# 		Config(f"user.role.{{{self.name}}}.privilege.product.groupaccess.productgroups", defaultValues=[self.product_group_access])
		# 	)
		# else:
		# 	self.configes.append(Config(f"user.role.{{{self.name}}}.privilege.product.groupaccess.configured", defaultValues=[False]))
		# 	self.configes.append(Config(f"user.role.{{{self.name}}}.privilege.product.groupaccess.productgroups", defaultValues=[]))

		# self.read_configes()
		self.create_configes()

	# def read_configes(self) -> None:
	# 	role_configs = self.backend.config_getObjects([[], {"configId": f"user.role.{{{self.name}}}*"}])
	# 	for config in role_configs:
	# 		logger.devel(config)
	# 		for key, conf in self.configes.items():
	# 			logger.devel(key)
	# 			logger.devel(conf)
	# 			if config.id == conf:
	# 				self.__setattr__(key, config.defaultValues)

	def create_configes(self) -> None:
		user_roles = self.backend.config_getObjects(configId="opsi.roles")[0]
		if user_roles and self.name not in user_roles.defaultValues:
			user_roles.append(self.name)
			self.backend.config_createObjects([Config("user.roles", defaultValues=user_roles)])
		for value_key, config in self.configes.items():
			current_conf = self.backend.config_getObjects(configId=config)
			if current_conf:
				self.__setattr__(value_key, current_conf[0].defaultValues)
			self.backend.config_createObjects([Config(config, defaultValues=[self.__getattribute__(value_key)])])
