# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.auth.role
"""

from typing import Self
from opsicommon.objects import UnicodeConfig
from opsiconfd.auth.rights import Rights


class Role(Rights):  # pylint: disable=too-many-instance-attributes
	role: Self | None = None

	def __init__(  # pylint: disable=too-many-arguments
		self,
		name: str = "",
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
		self.config_prefix = f"user.role.{{{self.name}}}"
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

		self.configs["role"] = UnicodeConfig(
			id=f"{self.config_prefix}.has_role", multiValue=False, defaultValues=[self.role]  # pylint: disable=no-member
		)

		self.read_configs()
		self.create_configs()
