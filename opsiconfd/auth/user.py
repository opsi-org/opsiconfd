# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.auth.user
"""

from opsicommon.objects import BoolConfig, UnicodeConfig
from opsicommon.types import forceBool

from opsiconfd.auth.rights import Rights
from opsiconfd.auth.role import Role
from opsiconfd.logging import logger


class User(Rights):  # pylint: disable=too-many-instance-attributes, too-few-public-methods
	name: str

	def __init__(  # pylint: disable=too-many-arguments
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
		self.config_prefix = f"user.{{{self.name}}}"

		super().__init__(
			name,
			read_only,
			create_client,
			opsi_server_write,
			depot_access,
			host_group_access,
			product_group_access,
			ssh_command_management,
			ssh_command,
			ssh_menu_server_console,
			ssh_server_configuration,
		)

		# if a role is set, all values are set by the role
		if role:
			self.role = role  # type: ignore[assignment]
			self.read_only = self.role.read_only  # type: ignore[union-attr]
			self.create_client = self.role.create_client  # type: ignore[union-attr]
			self.opsi_server_write = self.role.opsi_server_write  # type: ignore[union-attr]
			self.depot_access = self.role.depot_access  # type: ignore[union-attr]
			self.host_group_access = self.role.host_group_access  # type: ignore[union-attr]
			self.product_group_access = self.role.product_group_access  # type: ignore[union-attr]
			self.ssh_command_management = self.role.ssh_command_management  # type: ignore[union-attr]
			self.ssh_command = self.role.ssh_command  # type: ignore[union-attr]
			self.ssh_menu_server_console = self.role.ssh_menu_server_console  # type: ignore[union-attr]
			self.ssh_server_configuration = self.role.ssh_server_configuration  # type: ignore[union-attr]

			self.configs["role"] = UnicodeConfig(
				id=f"{self.config_prefix}.has_role",
				multiValue=False,
				defaultValues=[self.role.name],  # type: ignore[union-attr] # pylint: disable=no-member
			)
		else:
			self.role = None
			self.configs["role"] = UnicodeConfig(
				id=f"{self.config_prefix}.has_role", multiValue=False, defaultValues=[]  # pylint: disable=no-member
			)
			self.read_configs()

		self.create_configs()

	def read_configs(self) -> None:
		from opsiconfd.backend import get_unprotected_backend  # pylint: disable=import-outside-toplevel

		backend = get_unprotected_backend()

		current_configs = backend.config_getObjects(configId=f"{self.config_prefix}.*")
		if not current_configs:
			return
		logger.devel(current_configs)
		for var, config in self.configs.items():
			if var == "modified":
				continue
			logger.devel(var)
			for current_config in current_configs:
				logger.devel(current_config)
				if current_config.id == config.id and current_config.defaultValues:
					logger.devel(current_config.defaultValues)
					if isinstance(config, BoolConfig):
						setattr(self, var, forceBool(current_config.defaultValues[0]))
					elif config.multiValue:
						setattr(self, var, current_config.defaultValues)
					elif var == "role":
						setattr(self, var, Role(current_config.defaultValues[0]))
					else:
						setattr(self, var, current_config.defaultValues[0])
					current_configs.remove(current_config)
					break


def create_user(name: str, groups: set) -> None:
	from opsiconfd.backend import get_unprotected_backend  # pylint: disable=import-outside-toplevel

	backend = get_unprotected_backend()

	user_register = backend.config_getObjects(configId="user.{}.register")
	if not user_register or (user_register and not backend.config_getObjects(configId="user.{}.register")[0].defaultValues[0]):
		return

	role = None
	groups_to_import = backend.config_getObjects(configId="opsi.roles")
	if groups_to_import:
		for group in groups:
			if group in groups_to_import[0].defaultValues:
				# use first match as role and skip other groups
				role = Role(group)
				break

	User(name=name, role=role)
