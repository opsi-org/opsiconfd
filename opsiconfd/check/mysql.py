# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""

from __future__ import annotations

from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.check.common import CheckResult, CheckStatus, exc_to_result


def check_mysql() -> CheckResult:
	"""
	## Check MySQL

	Checks whether the database is accessible.
	The data from the file /etc/opsi/backends/mysql.conf is used for the connection.
	If no connection can be established, this is an error.
	"""
	result = CheckResult(check_id="mysql", check_name="MySQL server", check_description="Check MySQL server state")
	with exc_to_result(result):
		mysql = MySQLConnection()
		with mysql.connection():
			result.check_status = CheckStatus.OK
			result.message = "Connection to MySQL is working."

	return result
