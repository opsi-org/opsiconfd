# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
poetry run python scripts/update-db-schema.py
"""

from pathlib import Path

from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.mysql.schema import read_database_schema

mysql = MySQLConnection()
mysql.connect()
create_code = read_database_schema(mysql).splitlines(keepends=True)
for idx, line in enumerate(create_code):
	pos = line.find(" REFERENCES ")
	if pos != -1:
		part1 = line[:pos] + "\n\t\t"
		part2 = line[pos + 1 :]
		pos = part2.find(" ON ")
		if pos != -1:
			part2 = part2[:pos] + "\n\t\t" + part2[pos + 1 :]
		create_code[idx] = part1 + part2

schema_file = Path(__file__).parent.parent / "opsiconfd/backend/mysql/schema.py"
lines = []
in_create_tables_sql = False  # pylint: disable=invalid-name
for line in schema_file.read_text(encoding="utf-8").splitlines(keepends=True):
	if line.startswith("CREATE_TABLES_SQL"):
		lines.append(line)
		lines.extend(create_code)
		in_create_tables_sql = True  # pylint: disable=invalid-name
	elif in_create_tables_sql and '"""' in line:
		in_create_tables_sql = False  # pylint: disable=invalid-name
	if not in_create_tables_sql:
		lines.append(line)

schema_file.write_text("".join(lines), encoding="utf-8")
