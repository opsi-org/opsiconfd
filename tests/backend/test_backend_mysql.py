# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.mysql
"""

import re
import textwrap
from pathlib import Path
from typing import Any

import pytest

from opsiconfd.backend.auth import RPCACE
from opsiconfd.backend.mysql import MySQLConnection
from tests.utils import backend, get_config  # pylint: disable=unused-import


def test_config_backend_mysql_conf(tmp_path: Path) -> None:
	config_file = tmp_path / "mysql.conf"
	with get_config({"backend_config_dir": str(tmp_path), "mysql_internal_url": None}):
		config = textwrap.dedent(
			"""
			# -*- coding: utf-8 -*-

			module = 'MySQL'
			config = {
				"username" : "usernameö$",
				"database" : "databaseö$",
				"address" : "addressö$",
				"password" : "passwordö$",
				"databaseCharset" : "charset",
				"connectionPoolMaxOverflow" : 11,
				"connectionPoolTimeout" : 12,
				"connectionPoolSize" : 13,
				"connectionPoolRecycling" : -1,
				"unique_hardware_addresses": True
			}
			"""
		)
		expected = {
			"username": "usernameö$",
			"database": "databaseö$",
			"address": "addressö$",
			"password": "passwordö$",
			"_database_charset": "charset",
			"_connection_pool_max_overflow": 11,
			"_connection_pool_timeout": 12,
			"_connection_pool_size": 13,
			"_connection_pool_recycling": -1,
			"unique_hardware_addresses": True,
		}
		config_file.write_text(config, encoding="utf-8")

		con = MySQLConnection()
		for key, value in expected.items():
			assert getattr(con, key) == value

		# Test unique_hardware_addresses = False
		config = textwrap.dedent(
			"""
			config = {
				"unique_hardware_addresses": False
			}
			"""
		)
		expected = {
			"unique_hardware_addresses": False,
		}
		config = "\n".join(line.strip() for line in config.split("\n"))
		config_file.write_text(config, encoding="utf-8")
		con = MySQLConnection()
		for key, value in expected.items():
			assert getattr(con, key) == value


def test_update_config_file(tmp_path: Path) -> None:
	config_file = tmp_path / "mysql.conf"
	with get_config({"backend_config_dir": str(tmp_path)}):
		config = textwrap.dedent(
			"""
			# -*- coding: utf-8 -*-

			module = 'MySQL'
			config = {
				"username" : "???",
				"database" : "???",
				"address" : "???",
				"password" : "???"
			}
			"""
		)
		config_file.write_text(config, encoding="utf-8")
		con = MySQLConnection()
		con.address = "address"
		con.database = "database"
		con.username = "username"
		con.password = "password"
		con.update_config_file()
		new_config = config_file.read_text(encoding="utf-8")
		assert new_config == textwrap.dedent(
			"""
			# -*- coding: utf-8 -*-

			module = 'MySQL'
			config = {
				"username" : "username",
				"database" : "database",
				"address" : "address",
				"password" : "password",
			}
			"""
		)


@pytest.mark.parametrize(
	"mysql_internal_url, expected_config",
	(
		(
			"mysql://mysql-host:3306/opsidb?databaseCharset=utf8&username=opsiuser&password=opsipass",
			{
				"username": "opsiuser",
				"database": "opsidb",
				"address": "mysql-host",
				"password": "opsipass",
				"_database_charset": "utf8mb4",
				"unique_hardware_addresses": True,
			},
		),
		(
			"mysql://username:p%C3%A4ssw%C3%B6rd%24@host:3306/opsidb?connectionPoolRecycling=100",
			{
				"username": "username",
				"database": "opsidb",
				"address": "host",
				"password": "pässwörd$",
				"_connection_pool_recycling": 100,
			},
		),
		(
			"mysql://u:p@localhost:3306/db?databaseCharset=charset"
			"&connectionPoolMaxOverflow=11&connectionPoolTimeout=12&connectionPoolSize=13&unique_hardware_addresses=0",
			{
				"username": "u",
				"database": "db",
				"address": "localhost",
				"password": "p",
				"_database_charset": "charset",
				"_connection_pool_max_overflow": 11,
				"_connection_pool_timeout": 12,
				"_connection_pool_size": 13,
				"_connection_pool_recycling": -1,
				"unique_hardware_addresses": False,
			},
		),
	),
)
def test_config_mysql_internal_url(tmp_path: Path, mysql_internal_url: str, expected_config: dict[str, Any]) -> None:
	config_file = tmp_path / "mysql.conf"
	with get_config({"backend_config_dir": str(tmp_path), "mysql_internal_url": mysql_internal_url}, with_env=False):
		config = textwrap.dedent(
			"""
			# -*- coding: utf-8 -*-

			module = 'MySQL'
			config = {
				"address" : "address"
			}
			"""
		)
		config_file.write_text(config, encoding="utf-8")

		con = MySQLConnection()
		for key, value in expected_config.items():
			assert getattr(con, key) == value


def test_connect() -> None:
	con = MySQLConnection()
	with con.connection():
		with con.session() as session:
			assert session.execute("SELECT 999").fetchone()[0] == 999


def exclude_test_big_query() -> None:
	con = MySQLConnection()
	with con.connection():
		with con.session() as session:
			where = " OR ".join("10000 = 10000" for i in range(1000000))
			query = f"SELECT * FROM HOST WHERE {where}"
			assert session.execute(query).fetchone()[0]


def test_get_columns() -> None:  # pylint: disable=too-many-branches
	allowed_attributes = {"id", "type", "description"}
	client_id = "client1.opsi.org"
	ace = [
		RPCACE(method_re=re.compile(".*"), type="self", id=client_id),
		RPCACE(method_re=re.compile(".*"), type="opsi_client", allowed_attributes=allowed_attributes),
	]
	con = MySQLConnection()
	with con.connection():
		selected_attributes = ["id", "type", "description", "opsiHostKey", "notes", "hardwareAddress", "created"]
		columns = con.get_columns(tables=["HOST"], ace=ace, attributes=selected_attributes)
		for col, info in columns.items():
			if col == "type":
				assert info.select == "`HOST`.`type`"
			elif col in selected_attributes:
				if col in allowed_attributes:
					assert info.select == f"IF(`HOST`.`hostId`='{client_id}',`HOST`.`{info.column}`,`HOST`.`{info.column}`)"
				else:
					assert info.select == f"IF(`HOST`.`hostId`='{client_id}',`HOST`.`{info.column}`,NULL)"
			else:
				assert info.select is None

	denied_attributes = {"opsiHostKey", "notes"}
	ace = [
		RPCACE(method_re=re.compile(".*"), type="self", id=client_id, denied_attributes=denied_attributes),
		RPCACE(method_re=re.compile(".*"), type="opsi_client", allowed_attributes=allowed_attributes),
	]
	with con.connection():
		selected_attributes = [
			"id",
			"type",
			"description",
			"opsiHostKey",
			"notes",
			"hardwareAddress",
			"lastSeen",
		]
		columns = con.get_columns(tables=["HOST"], ace=ace, attributes=selected_attributes)
		for col, info in columns.items():
			if col == "type":
				assert info.select == "`HOST`.`type`"
			elif col in selected_attributes:
				if col in denied_attributes:
					assert info.select is None
				elif col in allowed_attributes:
					assert info.select == f"IF(`HOST`.`hostId`='{client_id}',`HOST`.`{info.column}`,`HOST`.`{info.column}`)"
				else:
					assert info.select == f"IF(`HOST`.`hostId`='{client_id}',`HOST`.`{info.column}`,NULL)"
			else:
				assert info.select is None
