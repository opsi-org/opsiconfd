# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.mysql
"""

from pathlib import Path
from typing import Any, Dict

import pytest

from opsiconfd.backend.mysql import MySQLBackend

from .utils import get_config


@pytest.mark.parametrize(
	"config, expected",
	[
		(
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
			"unique_hardware_addresses": True
		}
		""",
			{
				"_username": "usernameö$",
				"_database": "databaseö$",
				"_address": "addressö$",
				"_password": "passwordö$",
				"_database_charset": "charset",
				"_connection_pool_max_overflow": 11,
				"_connection_pool_timeout": 12,
				"_connection_pool_size": 13,
				"_unique_hardware_addresses": True,
			},
		),
		(
			"""
		config = {
			"unique_hardware_addresses": False
		}
		""",
			{
				"_unique_hardware_addresses": False,
			},
		),
	],
)
def test_config(tmp_path: Path, config: str, expected: Dict[str, Any]) -> None:
	config_file = tmp_path / "mysql.conf"
	config = "\n".join(line.strip() for line in config.split("\n"))
	config_file.write_text(config, encoding="utf-8")
	with get_config({"backend_config_dir": str(tmp_path)}):
		backend = MySQLBackend()
		for key, value in expected.items():
			assert getattr(backend, key) == value


def test_connect() -> None:
	backend = MySQLBackend()
	backend.connect()
	with backend.session() as session:
		assert session.execute("SELECT 999").fetchone()[0] == 999
