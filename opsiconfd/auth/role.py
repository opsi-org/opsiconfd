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
from opsicommon.types import forceBool


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
	configes: dict[str, dict] = {}

	def __init__(
		self,
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
			"role": {"configId": f"user.role.{{{self.name}}}.has_role", "type": "UnicodeConfig", "multiValue": False},
			"modified": {"configId": f"user.role.{{{self.name}}}.modified", "type": "UnicodeConfig", "multiValue": False},
			"read_only": {"configId": f"user.role.{{{self.name}}}.privilege.host.all.registered_readonly", "type": "BoolConfig"},
			"create_client": {"configId": f"user.role.{{{self.name}}}.privilege.host.createclient", "type": "BoolConfig"},
			"opsi_server_write": {"configId": f"user.role.{{{self.name}}}.privilege.host.opsiserver.write", "type": "BoolConfig"},
			"ssh_command_management": {"configId": f"user.role.{{{self.name}}}.ssh.commandmanagement.active", "type": "BoolConfig"},
			"ssh_command": {"configId": f"user.role.{{{self.name}}}.ssh.commands.active", "type": "BoolConfig"},
			"ssh_menu_server_console": {"configId": f"user.role.{{{self.name}}}.ssh.menu_serverconsole.active", "type": "BoolConfig"},
			"ssh_server_configuration": {"configId": f"user.role.{{{self.name}}}.ssh.serverconfiguration.active", "type": "BoolConfig"},
			"depot_access_configured": {
				"configId": f"user.role.{{{self.name}}}.privilege.host.depotaccess.configured",
				"type": "BoolConfig",
			},
			"depot_access": {
				"configId": f"user.role.{{{self.name}}}.privilege.host.depotaccess.depots",
				"type": "UnicodeConfig",
				"multiValue": True,
			},
			"host_group_access_configured": {
				"configId": f"user.role.{{{self.name}}}.privilege.host.groupaccess.configured",
				"type": "BoolConfig",
			},
			"host_group_access": {
				"configId": f"user.role.{{{self.name}}}.privilege.host.groupaccess.hostgroups",
				"type": "UnicodeConfig",
				"multiValue": True,
			},
			"product_group_access_configured": {
				"configId": f"user.role.{{{self.name}}}.privilege.product.groupaccess.configured",
				"type": "BoolConfig",
			},
			"product_group_access": {
				"configId": f"user.role.{{{self.name}}}.privilege.product.groupaccess.productgroups",
				"type": "UnicodeConfig",
				"multiValue": True,
			},
		}

		self.create_configs()

	def create_configs(self) -> None:
		from opsiconfd.backend import (
			get_unprotected_backend,  # pylint: disable=import-outside-toplevel
		)

		backend = get_unprotected_backend()

		user_roles = backend.config_getObjects(configId="opsi.roles")

		if user_roles and self.name not in user_roles[0].defaultValues:
			user_roles[0].defaultValues.append(self.name)
			backend.config_createUnicode(id="opsi.roles", defaultValues=user_roles[0].defaultValues, multiValue=True)
		for value_key, config in self.configes.items():
			current_conf = backend.config_getObjects(configId=config["configId"])
			if current_conf:
				if config["type"] == "BoolConfig":
					self.__setattr__(value_key, forceBool(current_conf[0].defaultValues[0]))
				elif config["multiValue"]:
					self.__setattr__(value_key, current_conf[0].defaultValues)
				else:
					self.__setattr__(value_key, current_conf[0].defaultValues[0])
			if config["type"] == "UnicodeConfig" and config["multiValue"]:
				backend.config_createUnicode(
					id=config["configId"], defaultValues=self.__getattribute__(value_key), multiValue=config["multiValue"]
				)
			elif config["type"] == "UnicodeConfig":
				backend.config_createUnicode(id=config["configId"], defaultValues=[self.__getattribute__(value_key)])
			else:
				backend.config_createBool(id=config["configId"], defaultValues=[self.__getattribute__(value_key)])
