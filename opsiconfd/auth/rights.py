# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.auth.rights
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Self

from opsicommon.objects import BoolConfig, UnicodeConfig
from opsicommon.types import forceBool

from opsiconfd.logging import logger


class Rights(ABC):  # pylint: disable=too-many-instance-attributes
	name: str
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
	configs: dict[str, UnicodeConfig | BoolConfig] = {}
	config_prefix: str = "user"

	def __init__(  # pylint: disable=too-many-arguments
		self,
		name: str,
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
		if depot_access:
			self.depot_access_configured = True
			self.depot_access = depot_access
		if host_group_access:
			self.host_group_access_configured = True
			self.host_group_access = host_group_access
		if product_group_access:
			self.product_group_access_configured = True
			self.product_group_access = product_group_access
		self.ssh_command_management = ssh_command_management
		self.ssh_command = ssh_command
		self.ssh_menu_server_console = ssh_menu_server_console
		self.ssh_server_configuration = ssh_server_configuration

		now = datetime.utcnow()
		self.modified = now.strftime("%Y-%m-%d %H:%M:%S")

		self.configs = {
			"role": UnicodeConfig(
				id=f"{self.config_prefix}.has_role",
				multiValue=False,
				editable=False,
				defaultValues=[""],
				description="which role should determine this users configuration",
			),
			"modified": UnicodeConfig(
				id=f"{self.config_prefix}.modified",
				multiValue=False,
				editable=False,
				defaultValues=[self.modified],
				description="last modification time for entries of this user",
			),
			"read_only": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.all.registered_readonly",
				description="the primary value setting is based on the user group",
			),
			"create_client": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.createclient",
				description="the primary value setting is false",
			),
			"opsi_server_write": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.opsiserver.write",
				description="the primary value setting is based on the user group",
			),
			"ssh_command_management": BoolConfig(
				id=f"{self.config_prefix}.ssh.commandmanagement.active", description="the primary value setting is based on the user group"
			),
			"ssh_command": BoolConfig(
				id=f"{self.config_prefix}.ssh.commands.active", description="the primary value setting is based on the user group"
			),
			"ssh_menu_server_console": BoolConfig(
				id=f"{self.config_prefix}.ssh.menu_serverconsole.active", description="the primary value setting is based on the user group"
			),
			"ssh_server_configuration": BoolConfig(
				id=f"{self.config_prefix}.ssh.serverconfiguration.active",
				description="the primary value setting is based on the user group",
			),
			"depot_access_configured": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.depotaccess.configured",
				description="the primary value setting is false",
			),
			"depot_access": UnicodeConfig(
				id=f"{self.config_prefix}.privilege.host.depotaccess.depots",
				multiValue=True,
				editable=False,
				description="the primary value setting is an empty selection list, but all existing items as option",
			),
			"host_group_access_configured": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.groupaccess.configured",
				description="the primary value setting is false",
			),
			"host_group_access": UnicodeConfig(
				id=f"{self.config_prefix}.privilege.host.groupaccess.hostgroups",
				multiValue=True,
				editable=False,
				description="the primary value setting is an empty selection list, but all existing items as option",
			),
			"product_group_access_configured": BoolConfig(
				id=f"{self.config_prefix}.privilege.product.groupaccess.configured",
				description="the primary value setting is false",
			),
			"product_group_access": UnicodeConfig(
				id=f"{self.config_prefix}.privilege.product.groupaccess.productgroups",
				multiValue=True,
				editable=False,
				description="the primary value setting is an empty selection list, but all existing items as option",
			),
		}

	# @abstractmethod
	# def read_configs(self) -> None:
	# 	pass

	def read_configs(self) -> None:
		from opsiconfd.backend import get_unprotected_backend  # pylint: disable=import-outside-toplevel

		backend = get_unprotected_backend()

		current_configs = backend.config_getObjects(configId=f"{self.config_prefix}.*")
		if not current_configs:
			return
		for var, config in self.configs.items():
			if var == "modified":
				continue
			for current_config in current_configs:
				logger.devel(current_config)
				if current_config.id == config.id and current_config.defaultValues:
					logger.devel(current_config.defaultValues)
					if isinstance(config, BoolConfig):
						setattr(self, var, forceBool(current_config.defaultValues[0]))
					elif config.multiValue:
						setattr(self, var, current_config.defaultValues)
					else:
						setattr(self, var, current_config.defaultValues[0])
					current_configs.remove(current_config)
					break

	def create_configs(self) -> None:
		from opsiconfd.backend import get_unprotected_backend  # pylint: disable=import-outside-toplevel

		logger.devel(self.configs)
		backend = get_unprotected_backend()
		for var, config in self.configs.items():
			# config.defaultValues = getattr(self, var)
			if isinstance(getattr(self, var), list):
				config.defaultValues = getattr(self, var)
			else:
				config.defaultValues = [getattr(self, var)]
		logger.devel(self.configs)
		backend.config_createObjects(list(self.configs.values()))
