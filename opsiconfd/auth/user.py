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


class User:
	backend = None
	name: str
	role: Role
	read_only: bool = False
	create_client: bool = True
	opsi_server_write: bool = True
	depot_access: list[str] | None = None
	host_group_access: list[str] | None = None
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

		self.create_configes()

	def create_configes(self) -> None:
		# pylint: disable=import-outside-toplevel

		now = datetime.utcnow()
		configes = [
			Config(f"user.{{{self.name}}}.has_role", defaultValues=[self.role.name]),
			Config(f"user.{{{self.name}}}.modified", defaultValues=[now.strftime("%Y-%m-%d %H:%M:%S")]),
		]

		self.backend.config_createObjects(configes)
