# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
setup tests
"""

from contextlib import nullcontext
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from opsi.opsi.service.model.object import OpsiConfigserver

from opsiconfd.backend.mysql import MySQLConnection, MySQLSession
from opsiconfd.setup.backend import file_mysql_migration, setup_mysql_user
from opsiconfd.setup.legacy_file_backend import LegacyFileBackendData
from opsiconfd.utils import get_primary_ip_interface

from .utils import get_config


@pytest.mark.parametrize(
	"mysql_address",
	("localhost", "/var/run/mysqld/mysqld.sock", "127.0.0.1", "::1", "10.10.1.2"),
)
def test_setup_mysql_user(mysql_address: str) -> None:
	root_mysql = MySQLConnection()
	root_mysql.connect()
	mysql = MySQLConnection()
	mysql.username = "test_user"
	statements = []

	def execute(self: MySQLSession, statement: str, params: Any | None = None) -> None:
		nonlocal statements
		statements.append(statement)
		if "ALTER USER" in statement:
			raise Exception("mock error")

	root_mysql.address = mysql_address
	with patch("opsiconfd.backend.mysql.MySQLSession.execute", execute):
		setup_mysql_user(root_mysql=root_mysql, mysql=mysql)
		expected_address = "localhost" if mysql_address != "10.10.1.2" else get_primary_ip_interface().ip.exploded
		assert statements == [
			f"CREATE USER IF NOT EXISTS 'test_user'@'{expected_address}'",
			f"ALTER USER 'test_user'@'{expected_address}' IDENTIFIED WITH mysql_native_password BY 'opsi'",
			f"ALTER USER 'test_user'@'{expected_address}' IDENTIFIED BY 'opsi'",
			f"SET PASSWORD FOR 'test_user'@'{expected_address}' = PASSWORD('opsi')",
			f"GRANT ALL ON opsi.* TO 'test_user'@'{expected_address}'",
			"FLUSH PRIVILEGES",
		]


def empty_legacy_data() -> LegacyFileBackendData:
	"""Return a migration snapshot containing only a configserver."""
	return LegacyFileBackendData(
		hosts=[OpsiConfigserver(id="server.test.invalid")],
		products=[],
		configs=[],
		groups=[],
		product_dependencies=[],
		product_properties=[],
		product_on_depots=[],
		product_on_clients=[],
		product_property_states=[],
		config_states=[],
		objects_to_groups=[],
	)


def test_file_mysql_migration_parses_before_database_drop(tmp_path: Path) -> None:
	"""A source parsing failure leaves the database and dispatch file untouched."""
	dispatch_conf = tmp_path / "dispatch.conf"
	dispatch_conf.write_text(".* : file\n", encoding="utf-8")
	with (
		get_config({"dispatch_config_file": str(dispatch_conf)}),
		patch("opsiconfd.setup.backend.LegacyFileBackendReader.read", side_effect=ValueError("invalid source")),
		patch("opsiconfd.setup.backend.drop_database") as drop_database_mock,
		pytest.raises(ValueError, match="invalid source"),
	):
		file_mysql_migration()

	assert dispatch_conf.exists()
	assert not dispatch_conf.with_suffix(".conf.old").exists()
	drop_database_mock.assert_not_called()


def test_file_mysql_migration_renames_dispatch_after_success(tmp_path: Path) -> None:
	"""A successful import archives the legacy dispatch configuration."""
	dispatch_conf = tmp_path / "dispatch.conf"
	dispatch_conf.write_text(".* : file, mysql\n", encoding="utf-8")
	mysql = MagicMock()
	mysql.disable_unique_hardware_addresses.return_value = nullcontext()
	mysql.disable_unique_systemUUIDs.return_value = nullcontext()
	backend = MagicMock()
	backend.events_disabled.return_value = nullcontext()
	legacy_data = empty_legacy_data()
	with (
		get_config({"dispatch_config_file": str(dispatch_conf)}),
		patch("opsiconfd.setup.backend.opsi_config.get", return_value="server.test.invalid"),
		patch("opsiconfd.setup.backend.LegacyFileBackendReader.read", return_value=legacy_data),
		patch("opsiconfd.setup.backend.get_mysql", return_value=mysql),
		patch("opsiconfd.backend.get_unprotected_backend", return_value=backend),
		patch("opsiconfd.setup.backend.drop_database"),
		patch("opsiconfd.setup.backend.create_database"),
		patch("opsiconfd.setup.backend.update_database"),
		patch("opsiconfd.setup.backend.import_legacy_file_backend") as import_mock,
	):
		file_mysql_migration()

	import_mock.assert_called_once_with(legacy_data, backend)
	assert not dispatch_conf.exists()
	assert dispatch_conf.with_suffix(".conf.old").read_text(encoding="utf-8") == ".* : file, mysql\n"
