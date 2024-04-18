# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from __future__ import annotations

from opsiconfd.backend.mysql import MAX_ALLOWED_PACKET, MySQLConnection
from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult, exc_to_result
from opsiconfd.logging import logger


def check_mysql() -> CheckResult:
	"""
	## Check MySQL

	Checks whether the database is accessible.
	The data from the file /etc/opsi/backends/mysql.conf is used for the connection.
	If no connection can be established, this is an error.
	"""
	result = CheckResult(
		check_id="mysql",
		check_name="MySQL server",
		check_description="Check MySQL server state",
		message="No MySQL issues found.",
	)
	with exc_to_result(result):
		mysql = MySQLConnection()
		with mysql.connection():
			with mysql.session() as session:
				result.add_partial_result(
					PartialCheckResult(
						check_id="mysql:connection",
						check_name="MySQL connection",
						check_status=CheckStatus.OK,
						message="Connection to MySQL is working",
					)
				)

				partial_result = PartialCheckResult(
					check_id="mysql:configuration",
					check_name="MySQL configuration",
					check_status=CheckStatus.OK,
					message="MySQL configuration is OK.",
				)
				res = session.execute("SHOW VARIABLES LIKE 'max_allowed_packet'").fetchone()
				max_allowed_packet = int(res[1]) if res else 0
				partial_result.details = {"max_allowed_packet": max_allowed_packet}
				if max_allowed_packet < MAX_ALLOWED_PACKET:
					partial_result.check_status = CheckStatus.ERROR
					partial_result.message = (
						f"Configured max_allowed_packet={max_allowed_packet} is too small (should be at least {MAX_ALLOWED_PACKET})."
					)
				result.add_partial_result(partial_result)

				if result.check_status != CheckStatus.OK:
					result.message = "Some issues found with MySQL."
	return result


def check_unique_hardware_addresses() -> CheckResult:
	"""
	## Check Unique Hardware Addresses

	Checks whether all hardware addresses are unique if unique_hardware_addresses is enabled.
	"""
	result = CheckResult(
		check_id="unique_hardware_addresses",
		check_name="Unique hardware addresses",
		check_description="Check if all hardware addresses are unique",
		message="All hardware addresses are unique.",
	)

	mysql = MySQLConnection()
	if not mysql.unique_hardware_addresses:
		result.message = "Unique hardware addresses check is disabled."
		return result
	with mysql.connection():
		with mysql.session() as session:
			res = session.execute(
				'SELECT COUNT(h.hardwareAddress) - COUNT(DISTINCT h.hardwareAddress) AS duplicate_values FROM HOST AS h WHERE h.hardwareaddress != "" AND h.hardwareAddress IS NOT NULL;'
			).fetchone()
			duplicate_values = res[0]

			logger.debug("duplicate_values: %s", duplicate_values)
			if duplicate_values > 0:
				result.message = "Some hardware addresses are not unique."
				result.check_status = CheckStatus.ERROR

			result.details = {"duplicate_values": duplicate_values}
	return result
