# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test user roles
"""

from datetime import datetime
from typing import Generator

import pytest_asyncio
from opsicommon.objects import BoolConfig, HostGroup, OpsiDepotserver, ProductGroup, UnicodeConfig
from sqlalchemy.orm import Session  # type: ignore

from opsiconfd.auth.role import Role
from opsiconfd.auth.user import User
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.rpc.main import UnprotectedBackend

from .utils import backend  # pylint: disable=unused-import


@pytest_asyncio.fixture(autouse=True)
def clean_configs_and_objects(backend: UnprotectedBackend) -> Generator:  # pylint: disable=redefined-outer-name
	mysql = MySQLConnection()
	with mysql.connection():
		with mysql.session() as session:
			delete_config_values(session)
			delete_hosts(session)
			delete_groups(session)
	backend.config_createBool(id="user.{}.register", defaultValues=True)

	backend.host_createObjects(
		[
			OpsiDepotserver(id="depot1.test.local"),
			OpsiDepotserver(id="depot2.test.local"),
			OpsiDepotserver(id="depot3.test.local"),
			OpsiDepotserver(id="depot4.test.local"),
		]
	)
	backend.group_createObjects(
		[
			ProductGroup(id="product1"),
			ProductGroup(id="product2"),
			ProductGroup(id="product3"),
			ProductGroup(id="product4"),
			HostGroup(id="group1"),
			HostGroup(id="group2"),
			HostGroup(id="group3"),
			HostGroup(id="group4"),
		]
	)

	yield
	with mysql.connection():
		with mysql.session() as session:
			delete_config_values(session)
			delete_hosts(session)
			delete_groups(session)


def delete_config_values(session: Session) -> None:
	session.execute("DELETE FROM `CONFIG_VALUE` WHERE configId LIKE 'user.%'")


def delete_hosts(session: Session) -> None:
	session.execute("DELETE FROM `HOST` WHERE `type` = 'OpsiDepotserver'")


def delete_groups(session: Session) -> None:
	session.execute("DELETE FROM `GROUP` WHERE `groupId` LIKE 'group%'")
	session.execute("DELETE FROM `GROUP` WHERE `groupId` LIKE 'product%'")


# Tests that a User object can be created with all parameters provided
def test_create_user_with_all_parameters() -> None:
	test_role = Role(
		name="test_role",
		read_only=True,
		create_client=False,
		opsi_server_write=False,
		depot_access=["depot1.test.local", "depot2.test.local"],
		host_group_access=["group1", "group2"],
		product_group_access=["product1", "product2"],
		ssh_command_management=True,
		ssh_command=False,
		ssh_menu_server_console=False,
		ssh_server_configuration=False,
	)

	# Assert that the Role object is created correctly
	assert test_role.name == "test_role"
	assert test_role.role == ""
	assert test_role.read_only is True
	assert test_role.create_client is False
	assert test_role.opsi_server_write is False
	assert test_role.depot_access == ["depot1.test.local", "depot2.test.local"]
	assert test_role.host_group_access == ["group1", "group2"]
	assert test_role.product_group_access == ["product1", "product2"]
	assert test_role.ssh_command_management is True
	assert test_role.ssh_command is False
	assert test_role.ssh_menu_server_console is False
	assert test_role.ssh_server_configuration is False

	# Create a User object with all parameters provided
	user = User(
		name="test_user",
		role=test_role.name,
		read_only=True,
		create_client=False,
		opsi_server_write=False,
		depot_access=["depot3.test.local", "depot4.test.local"],
		host_group_access=["group3", "group4"],
		product_group_access=["product3", "product4"],
		ssh_command_management=True,
		ssh_command=False,
		ssh_menu_server_console=False,
		ssh_server_configuration=False,
	)

	# Assert that the User object is created correctly
	assert user.name == "test_user"
	assert user.role == test_role.name
	assert user.read_only is True
	assert user.create_client is False
	assert user.opsi_server_write is False
	assert user.depot_access == ["depot1.test.local", "depot2.test.local"]
	assert user.host_group_access == ["group1", "group2"]
	assert user.product_group_access == ["product1", "product2"]
	assert user.ssh_command_management is True
	assert user.ssh_command is False
	assert user.ssh_menu_server_console is False
	assert user.ssh_server_configuration is False


# Tests that a User object can be created with only the required parameters provided
def test_create_user_with_required_parameters() -> None:
	# Create a User object with only the required parameters provided
	user = User(name="test_user")

	# Assert that the User object is created correctly
	assert user.name == "test_user"
	assert user.role == ""
	assert user.read_only is False
	assert user.create_client is True
	assert user.opsi_server_write is True
	assert user.depot_access is None
	assert user.host_group_access is None
	assert user.product_group_access is None
	assert user.ssh_command_management is False
	assert user.ssh_command is True
	assert user.ssh_menu_server_console is True
	assert user.ssh_server_configuration is True


# Tests that a User object can be created with a Role object and override some values
def test_create_user_with_role_object_and_override_values() -> None:
	test_role = Role(
		name="test_role",
		read_only=True,
		create_client=False,
		opsi_server_write=False,
		depot_access=["depot1.test.local", "depot2.test.local"],
		host_group_access=["group1", "group2"],
		product_group_access=["product1", "product2"],
		ssh_command_management=True,
		ssh_command=False,
		ssh_menu_server_console=False,
		ssh_server_configuration=False,
	)

	# Assert that the Role object is created correctly
	assert test_role.name == "test_role"
	assert test_role.role == ""
	assert test_role.read_only is True
	assert test_role.create_client is False
	assert test_role.opsi_server_write is False
	assert test_role.depot_access == ["depot1.test.local", "depot2.test.local"]
	assert test_role.host_group_access == ["group1", "group2"]
	assert test_role.product_group_access == ["product1", "product2"]
	assert test_role.ssh_command_management is True
	assert test_role.ssh_command is False
	assert test_role.ssh_menu_server_console is False
	assert test_role.ssh_server_configuration is False

	# Create a User object with a Role object and override some values
	user = User(
		name="test_user",
		role=test_role.name,
		read_only=False,
		create_client=True,
		opsi_server_write=True,
		depot_access=["depot3", "depot4"],
		host_group_access=["group3", "group4"],
		product_group_access=["product3", "product4"],
		ssh_command_management=True,
		ssh_command=False,
		ssh_menu_server_console=False,
		ssh_server_configuration=False,
	)

	# Assert that the User object is created correctly
	assert user.name == "test_user"
	assert user.role == test_role.name
	assert user.read_only is True
	assert user.create_client is False
	assert user.opsi_server_write is False


def test_read_configs_for_user(backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	test_configs = [
		UnicodeConfig(id="user.{admin}.modified", defaultValues=["2022-01-01 00:00:00"]),
		BoolConfig(id="user.{admin}.privilege.host.all.registered_readonly", defaultValues=[True]),
		BoolConfig(id="user.{admin}.privilege.host.createclient", defaultValues=[False]),
		BoolConfig(id="user.{admin}.privilege.host.opsiserver.write", defaultValues=[False]),
		BoolConfig(id="user.{admin}.ssh.commandmanagement.active", defaultValues=[True]),
		BoolConfig(id="user.{admin}.ssh.commands.active", defaultValues=[False]),
		BoolConfig(id="user.{admin}.ssh.menu_serverconsole.active", defaultValues=[False]),
		BoolConfig(id="user.{admin}.ssh.serverconfiguration.active", defaultValues=[False]),
		BoolConfig(id="user.{admin}.privilege.host.depotaccess.configured", defaultValues=[True]),
		UnicodeConfig(
			id="user.{admin}.privilege.host.depotaccess.depots",
			possibleValues=["depot1.test.local", "depot2.test.local"],
			defaultValues=["depot1.test.local", "depot2.test.local"],
		),
		BoolConfig(id="user.{admin}.privilege.host.groupaccess.configured", defaultValues=[True]),
		UnicodeConfig(
			id="user.{admin}.privilege.host.groupaccess.hostgroups", possibleValues=["group1", "group2"], defaultValues=["group1", "group2"]
		),
		BoolConfig(id="user.{admin}.privilege.product.groupaccess.configured", defaultValues=[True]),
		UnicodeConfig(
			id="user.{admin}.privilege.product.groupaccess.productgroups",
			possibleValues=["product1", "product2"],
			defaultValues=["product1", "product2"],
		),
	]

	result = backend.config_createObjects(test_configs)
	print(result)
	now = datetime.utcnow()
	time = now.strftime("%Y-%m-%d %H:%M:%S")
	user = User(name="admin")
	user.read_configs()
	assert user.modified == time
	assert user.read_only is True
	assert user.create_client is False
	assert user.opsi_server_write is False
	assert user.ssh_command_management is True
	assert user.ssh_command is False
	assert user.ssh_menu_server_console is False
	assert user.ssh_server_configuration is False
	assert user.depot_access_configured is True
	assert user.depot_access == ["depot1.test.local", "depot2.test.local"]
	assert user.host_group_access_configured is True
	assert user.host_group_access == ["group1", "group2"]
	assert user.product_group_access_configured is True
	assert user.product_group_access == ["product1", "product2"]


# Tests that a Role object can be created with default values
def test_create_role_with_default_values() -> None:
	role = Role()
	assert role.name == ""
	assert role.read_only is False
	assert role.create_client is True
	assert role.opsi_server_write is True
	assert role.depot_access_configured is False
	assert role.depot_access is None
	assert role.host_group_access_configured is False
	assert role.host_group_access is None
	assert role.product_group_access_configured is False
	assert role.product_group_access is None
	assert role.ssh_command_management is False
	assert role.ssh_command is True
	assert role.ssh_menu_server_console is True
	assert role.ssh_server_configuration is True
	assert role.role == ""
	assert role.modified != ""
	assert isinstance(role.configs["modified"], UnicodeConfig)
	assert isinstance(role.configs["read_only"], BoolConfig)
	assert isinstance(role.configs["create_client"], BoolConfig)
	assert isinstance(role.configs["opsi_server_write"], BoolConfig)
	assert isinstance(role.configs["ssh_command_management"], BoolConfig)
	assert isinstance(role.configs["ssh_command"], BoolConfig)
	assert isinstance(role.configs["ssh_menu_server_console"], BoolConfig)
	assert isinstance(role.configs["ssh_server_configuration"], BoolConfig)
	assert isinstance(role.configs["depot_access_configured"], BoolConfig)
	assert isinstance(role.configs["depot_access"], UnicodeConfig)
	assert isinstance(role.configs["host_group_access_configured"], BoolConfig)
	assert isinstance(role.configs["host_group_access"], UnicodeConfig)
	assert isinstance(role.configs["product_group_access_configured"], BoolConfig)
	assert isinstance(role.configs["product_group_access"], UnicodeConfig)


def test_read_configs_for_role(backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	test_configs = [
		UnicodeConfig(id="user.role.{admin}.modified", defaultValues=["2022-01-01 00:00:00"]),
		BoolConfig(id="user.role.{admin}.privilege.host.all.registered_readonly", defaultValues=[True]),
		BoolConfig(id="user.role.{admin}.privilege.host.createclient", defaultValues=[False]),
		BoolConfig(id="user.role.{admin}.privilege.host.opsiserver.write", defaultValues=[False]),
		BoolConfig(id="user.role.{admin}.ssh.commandmanagement.active", defaultValues=[True]),
		BoolConfig(id="user.role.{admin}.ssh.commands.active", defaultValues=[False]),
		BoolConfig(id="user.role.{admin}.ssh.menu_serverconsole.active", defaultValues=[False]),
		BoolConfig(id="user.role.{admin}.ssh.serverconfiguration.active", defaultValues=[False]),
		BoolConfig(id="user.role.{admin}.privilege.host.depotaccess.configured", defaultValues=[True]),
		UnicodeConfig(
			id="user.role.{admin}.privilege.host.depotaccess.depots",
			possibleValues=["depot1.test.local", "depot2.test.local"],
			defaultValues=["depot1.test.local", "depot2.test.local"],
		),
		BoolConfig(id="user.role.{admin}.privilege.host.groupaccess.configured", defaultValues=[True]),
		UnicodeConfig(
			id="user.role.{admin}.privilege.host.groupaccess.hostgroups",
			possibleValues=["group1", "group2"],
			defaultValues=["group1", "group2"],
		),
		BoolConfig(id="user.role.{admin}.privilege.product.groupaccess.configured", defaultValues=[True]),
		UnicodeConfig(
			id="user.role.{admin}.privilege.product.groupaccess.productgroups",
			possibleValues=["product1", "product2"],
			defaultValues=["product1", "product2"],
		),
	]

	result = backend.config_updateObjects(test_configs)
	print(result)
	now = datetime.utcnow()
	time = now.strftime("%Y-%m-%d %H:%M:%S")
	role = Role(name="admin")
	role.read_configs()
	assert role.modified == time
	assert role.read_only is True
	assert role.create_client is False
	assert role.opsi_server_write is False
	assert role.ssh_command_management is True
	assert role.ssh_command is False
	assert role.ssh_menu_server_console is False
	assert role.ssh_server_configuration is False
	assert role.depot_access_configured is True
	assert role.depot_access == ["depot1.test.local", "depot2.test.local"]
	assert role.host_group_access_configured is True
	assert role.host_group_access == ["group1", "group2"]
	assert role.product_group_access_configured is True
	assert role.product_group_access == ["product1", "product2"]
