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
	configes: dict[str, Config] = {}

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
		self.configes = {
			"role": Config(f"user.role.{{{self.name}}}.has_role"),
			"modified": Config(f"user.role.{{{self.name}}}.modified", defaultValues=[now.strftime("%Y-%m-%d %H:%M:%S")]),
			"read_only": Config(f"user.role.{{{self.name}}}.privilege.host.all.registered_readonly", defaultValues=[self.read_only]),
			"create_client": Config(f"user.role.{{{self.name}}}.privilege.host.createclient", defaultValues=[self.create_client]),
			"opsi_server_write": Config(
				f"user.role.{{{self.name}}}.privilege.host.opsiserver.write", defaultValues=[self.opsi_server_write]
			),
			"ssh_command_management": Config(
				f"user.role.{{{self.name}}}.ssh.commandmanagement.active", defaultValues=[self.ssh_command_management]
			),
			"ssh_command": Config(f"user.role.{{{self.name}}}.ssh.commands.active", defaultValues=[self.ssh_command]),
			"ssh_menu_server_console": Config(
				f"user.role.{{{self.name}}}.ssh.menu_serverconsole.active", defaultValues=[self.ssh_menu_server_console]
			),
			"ssh_server_configuration": Config(
				f"user.role.{{{self.name}}}.ssh.serverconfiguration.active", defaultValues=[self.ssh_server_configuration]
			),
			"depot_access_configured": Config(
				f"user.role.{{{self.name}}}.privilege.host.depotaccess.configured", defaultValues=[self.depot_access]
			),
			"depot_access": Config(f"user.role.{{{self.name}}}.privilege.host.depotaccess.depots", defaultValues=[self.depot_access]),
			"host_group_access_configured": Config(
				f"user.role.{{{self.name}}}.privilege.host.groupaccess.configured", defaultValues=[self.host_group_access]
			),
			"host_group_access": Config(
				f"user.role.{{{self.name}}}.privilege.host.groupaccess.hostgroups", defaultValues=[self.host_group_access]
			),
			"product_group_access_configured": Config(
				f"user.role.{{{self.name}}}.privilege.product.groupaccess.configured", defaultValues=[self.product_group_access]
			),
			"product_group_access": Config(
				f"user.role.{{{self.name}}}.privilege.product.groupaccess.productgroups", defaultValues=[self.product_group_access]
			),
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

		self.read_configes()
		self.create_configes()

	def read_configes(self) -> None:
		role_configs = self.backend.config_getObjects([[], {"configId": f"user.role.{{{self.name}}}*"}])
		for config in role_configs:
			for key, conf in self.configes.items():
				logger.devel(key)
				logger.devel(conf)
				# if config.id == conf.id:

				#  self.__setattr__(key, config.defaultValues)
				#  conf.defaultValues = config.defaultValues

	def create_configes(self) -> None:
		self.backend.config_createObjects(self.configes.values)
