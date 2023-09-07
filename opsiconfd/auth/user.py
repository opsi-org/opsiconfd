# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.auth.user
"""

from opsicommon.objects import UnicodeConfig
from opsiconfd.auth.role import Role
from opsiconfd.logging import logger
from opsiconfd.auth.rights import Rights


class User(Rights):  # pylint: disable=too-many-instance-attributes, too-few-public-methods
	role: Role | None = None
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
			self.role = role
			self.read_only = self.role.read_only
			self.create_client = self.role.create_client
			self.opsi_server_write = self.role.opsi_server_write
			self.depot_access = self.role.depot_access
			self.host_group_access = self.role.host_group_access
			self.product_group_access = self.role.product_group_access
			self.ssh_command_management = self.role.ssh_command_management
			self.ssh_command = self.role.ssh_command
			self.ssh_menu_server_console = self.role.ssh_menu_server_console
			self.ssh_server_configuration = self.role.ssh_server_configuration

			self.configs["role"] = UnicodeConfig(
				id=f"{self.config_prefix}.has_role", multiValue=False, defaultValues=self.role.name  # pylint: disable=no-member
			)
		else:
			self.configs["role"] = UnicodeConfig(
				id=f"{self.config_prefix}.has_role", multiValue=False, defaultValues=[]  # pylint: disable=no-member
			)
			self.read_configs()

		self.create_configs()


def create_user(name: str, groups: set) -> None:
	from opsiconfd.backend import get_unprotected_backend  # pylint: disable=import-outside-toplevel

	backend = get_unprotected_backend()

	logger.devel(backend.config_getObjects(configId="user.{}.register")[0])
	if not backend.config_getObjects(configId="user.{}.register")[0].defaultValues[0]:
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
