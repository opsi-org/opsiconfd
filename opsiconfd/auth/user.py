# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.auth.user
"""

from opsi.opsi.service.model.object import UnicodeConfig

from opsiconfd.auth.rights import MessageTypes, Rights, Terminals
from opsiconfd.auth.role import Role
from opsiconfd.logging import get_logger

logger = get_logger("opsiconfd.user_roles")


class User(Rights):
	name: str

	def __init__(
		self,
		name: str,
		role: str = "",
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
		connect_terminal_forbidden: list[Terminals] | None = None,
		message_of_the_day_forbidden: list[MessageTypes] | None = None,
	):
		self.name = name
		self.config_prefix = f"user.{{{self.name}}}"

		super().__init__(
			name,
			read_only,
			create_client,
			opsi_server_write,
			depot_access_configured,
			depot_access,
			host_group_access_configured,
			host_group_access,
			product_group_access_configured,
			product_group_access,
			ssh_command_management,
			ssh_command,
			ssh_menu_server_console,
			ssh_server_configuration,
			connect_terminal_forbidden,
			message_of_the_day_forbidden,
		)

		self.read_configs()

		# if a role is set, all values are set by the role
		if role:
			logger.debug("Creating user %s with role %s", name, role)
			user_role = Role(name=role)
			self.role = role
			self.read_only = user_role.read_only
			self.create_client = user_role.create_client
			self.opsi_server_write = user_role.opsi_server_write
			self.depot_access = user_role.depot_access
			self.host_group_access = user_role.host_group_access
			self.product_group_access = user_role.product_group_access
			self.depot_access_configured = user_role.depot_access_configured
			self.host_group_access_configured = user_role.host_group_access_configured
			self.product_group_access_configured = user_role.product_group_access_configured
			self.ssh_command_management = user_role.ssh_command_management
			self.ssh_command = user_role.ssh_command
			self.ssh_menu_server_console = user_role.ssh_menu_server_console
			self.ssh_server_configuration = user_role.ssh_server_configuration
			self.connect_terminal_forbidden = user_role.connect_terminal_forbidden
			self.message_of_the_day_forbidden = user_role.message_of_the_day_forbidden
			roles = {r.id.split(".")[2].strip("{}") for r in self.backend.config_getObjects(configId="user.role.*")}
			self.configs["role"] = UnicodeConfig(
				id=f"{self.config_prefix}.has_role",
				multiValue=False,
				editable=False,
				defaultValues=[self.role],
				possibleValues=list(roles),
				description="Which role should determine this users configuration.",
			)
		else:
			logger.debug("Creating user %s", name)
			self.read_configs()
			if self.role:
				logger.debug("User %s has role %s", name, self.role)
		self.create_configs()


def create_user_roles(name: str, groups: set | None = None) -> None:
	from opsiconfd.backend import get_unprotected_backend

	if groups is None:
		groups = set()
	logger.debug("Creating user %s with groups %s", name, groups)
	backend = get_unprotected_backend()

	user_register = backend.config_getObjects(configId="user.{}.register")
	if not user_register or not user_register[0].defaultValues or not user_register[0].defaultValues[0]:
		return
	role = ""
	try:
		role = backend.config_getObjects(configId=f"user.{{{name}}}.has_role")[0].defaultValues[0]
	except IndexError:
		logger.debug("No role configured for user %s", name)
	logger.debug("Configured role for user %s: %s", name, role)
	groups_to_import = backend.config_getObjects(configId="opsi.roles")
	if groups_to_import and not role:
		logger.debug("Importing groups for user %s", name)
		logger.debug("Groups to import: %s", groups_to_import)
		for group in groups:
			logger.debug("Checking group %s", group)
			if group in groups_to_import[0].defaultValues:
				# use first match as role and skip other groups
				logger.debug("Use group %s as role for user %s.", group, name)
				role = str(group)
				break

	User(name=name, role=role)


def get_users() -> set[str]:
	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()
	user_configs = backend.config_getObjects(configId="user.{*")
	users = set()
	for config in user_configs:
		users.add(config.id.split(".")[1].strip("{}"))
	return users
