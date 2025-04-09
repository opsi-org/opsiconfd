# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
setup tests
"""

from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy.engine.result import Result  # type: ignore[import]

from opsiconfd.backend.mysql import MySQLConnection, MySQLSession
from opsiconfd.setup.backend import setup_mysql_user
from opsiconfd.utils import get_primary_ip_interface


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

	def execute(self: MySQLSession, statement: str, params: Any | None = None) -> Result:
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
