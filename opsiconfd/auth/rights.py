# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.auth.rights
"""


from datetime import datetime

from opsicommon.objects import BoolConfig, UnicodeConfig
from opsicommon.types import forceBool


class Rights:
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

	# @property
	# def depot_access_configured(self) -> bool:
	# 	return bool(self.depot_access)

	# @property
	# def host_group_access_configured(self) -> bool:
	# 	return bool(self.host_group_access)

	# @property
	# def product_group_access_configured(self) -> bool:
	# 	return bool(self.product_group_access)

	def __init__(
		self,
		name: str,
		read_only: bool = False,
		create_client: bool = True,
		opsi_server_write: bool = True,
		depot_access_configured: bool = False,
		depot_access: list[str] | None = None,
		host_group_access_configured: bool = False,
		host_group_access: list[str] | None = None,
		product_group_access_configured: bool = False,
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
		self.depot_access_configured = depot_access_configured
		self.depot_access = depot_access
		self.host_group_access_configured = host_group_access_configured
		self.host_group_access = host_group_access
		self.product_group_access_configured = product_group_access_configured
		self.product_group_access = product_group_access
		self.ssh_command_management = ssh_command_management
		self.ssh_command = ssh_command
		self.ssh_menu_server_console = ssh_menu_server_console
		self.ssh_server_configuration = ssh_server_configuration

		now = datetime.utcnow()
		self.modified = now.strftime("%Y-%m-%d %H:%M:%S")

		from opsiconfd.backend import get_unprotected_backend

		self.backend = get_unprotected_backend()
		depots = [depot.id for depot in self.backend.host_getObjects(type="OpsiDepotserver")]
		product_groups = [group.id for group in self.backend.group_getObjects(type="ProductGroup")]
		host_groups = [group.id for group in self.backend.group_getObjects(type="HostGroup")]

		self.configs = {
			"role": UnicodeConfig(
				id=f"{self.config_prefix}.has_role",
				multiValue=False,
				editable=False,
				defaultValues=[""],
				description="Which role should determine this users configuration.",
			),
			"modified": UnicodeConfig(
				id=f"{self.config_prefix}.modified",
				multiValue=False,
				editable=False,
				defaultValues=[self.modified],
				description="Last modification time for entries of this user.",
			),
			"read_only": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.all.registered_readonly",
				description="The primary value setting is based on the user group.",
			),
			"create_client": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.createclient",
				description="The primary value setting is false.",
			),
			"opsi_server_write": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.opsiserver.write",
				description="The primary value setting is based on the user group.",
			),
			"ssh_command_management": BoolConfig(
				id=f"{self.config_prefix}.ssh.commandmanagement.active", description="The primary value setting is based on the user group."
			),
			"ssh_command": BoolConfig(
				id=f"{self.config_prefix}.ssh.commands.active", description="The primary value setting is based on the user group."
			),
			"ssh_menu_server_console": BoolConfig(
				id=f"{self.config_prefix}.ssh.menu_serverconsole.active",
				description="The primary value setting is based on the user group.",
			),
			"ssh_server_configuration": BoolConfig(
				id=f"{self.config_prefix}.ssh.serverconfiguration.active",
				description="The primary value setting is based on the user group.",
			),
			"depot_access_configured": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.depotaccess.configured",
				description="The primary value setting is false.",
			),
			"depot_access": UnicodeConfig(
				id=f"{self.config_prefix}.privilege.host.depotaccess.depots",
				multiValue=True,
				editable=False,
				description="The primary value setting is an empty selection list, but all existing items as option.",
				defaultValues=[],
				possibleValues=depots,
			),
			"host_group_access_configured": BoolConfig(
				id=f"{self.config_prefix}.privilege.host.groupaccess.configured",
				description="the primary value setting is false",
			),
			"host_group_access": UnicodeConfig(
				id=f"{self.config_prefix}.privilege.host.groupaccess.hostgroups",
				multiValue=True,
				editable=False,
				description="The primary value setting is an empty selection list, but all existing items as option.",
				defaultValues=[],
				possibleValues=host_groups,
			),
			"product_group_access_configured": BoolConfig(
				id=f"{self.config_prefix}.privilege.product.groupaccess.configured",
				description="The primary value setting is false",
			),
			"product_group_access": UnicodeConfig(
				id=f"{self.config_prefix}.privilege.product.groupaccess.productgroups",
				multiValue=True,
				editable=False,
				description="The primary value setting is an empty selection list, but all existing items as option.",
				defaultValues=[],
				possibleValues=product_groups,
			),
		}

	def read_configs(self) -> None:
		current_configs = [
			config for config in self.backend.config_getObjects(configId=f"{self.config_prefix}.*") if config.defaultValues != []
		]
		if not current_configs:
			return
		for config_name, config in self.configs.items():
			# modification date should always be new
			if config_name in ("modified"):
				continue
			for current_config in current_configs:
				if current_config.id == config.id:
					if isinstance(config, BoolConfig):
						setattr(self, config_name, forceBool(current_config.defaultValues[0]))
					elif config.multiValue:
						setattr(self, config_name, current_config.defaultValues)
					else:
						setattr(self, config_name, current_config.defaultValues[0])
					current_configs.remove(current_config)
					break

	def create_configs(self) -> None:
		for config_name, config in self.configs.items():
			if isinstance(getattr(self, config_name), list):
				config.defaultValues = getattr(self, config_name)
			else:
				config.defaultValues = [getattr(self, config_name)]

		self.backend.config_updateObjects(list(self.configs.values()))
