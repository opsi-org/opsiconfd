# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.mysql
"""

import re
from pathlib import Path

from opsiconfd.backend.auth import RPCACE
from opsiconfd.backend.mysql import MySQLConnection

from ..utils import get_config


def test_config(tmp_path: Path) -> None:
	config_file = tmp_path / "mysql.conf"
	with get_config({"backend_config_dir": str(tmp_path)}):
		config = """
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
				"unique_hardware_addresses": True
			}
			"""
		expected = {
			"username": "usernameö$",
			"database": "databaseö$",
			"address": "addressö$",
			"password": "passwordö$",
			"_database_charset": "charset",
			"_connection_pool_max_overflow": 11,
			"_connection_pool_timeout": 12,
			"_connection_pool_size": 13,
			"unique_hardware_addresses": True,
		}
		config = "\n".join(line.strip() for line in config.split("\n"))
		config_file.write_text(config, encoding="utf-8")

		con = MySQLConnection()
		for key, value in expected.items():
			assert getattr(con, key) == value

		# Test unique_hardware_addresses = False
		config = """
			config = {
				"unique_hardware_addresses": False
			}
			"""
		expected = {
			"unique_hardware_addresses": False,
		}
		config = "\n".join(line.strip() for line in config.split("\n"))
		config_file.write_text(config, encoding="utf-8")
		con = MySQLConnection()
		for key, value in expected.items():
			assert getattr(con, key) == value


def test_connect() -> None:
	con = MySQLConnection()
	with con.connection():
		with con.session() as session:
			assert session.execute("SELECT 999").fetchone()[0] == 999


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
