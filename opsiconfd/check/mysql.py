# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """


import re
from dataclasses import dataclass

from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import-untyped]
from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd.backend.mysql import MAX_ALLOWED_PACKET, MySQLConnection
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager, exc_to_result
from opsiconfd.logging import logger


@dataclass()
class MysqlConfigurationCheck(Check):
	id: str = "mysql:configuration"
	name: str = "MySQL Configuration"
	description: str = "Check MySQL configuration"
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="MySQL configuration is OK.",
			check_status=CheckStatus.OK,
		)

		with exc_to_result(result):
			mysql = MySQLConnection()
			with mysql.connection():
				with mysql.session() as session:
					res = session.execute("SHOW VARIABLES LIKE 'max_allowed_packet'").fetchone()
					max_allowed_packet = int(res[1]) if res else 0
					if max_allowed_packet < MAX_ALLOWED_PACKET:
						result.check_status = CheckStatus.ERROR
						result.message = (
							f"Configured max_allowed_packet={max_allowed_packet} is too small (should be at least {MAX_ALLOWED_PACKET})."
						)
		return result


@dataclass()
class MysqlCheck(Check):
	id: str = "mysql"
	name: str = "MySQL"
	description: str = "Check MySQL server state"
	documentation: str = """
		## Check MySQL

		Checks whether the database is accessible.
		The data from the file /etc/opsi/backends/mysql.conf is used for the connection.
		If no connection can be established, this is an error.
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No MySQL issues found.",
			check_status=CheckStatus.OK,
		)

		try:
			mysql = MySQLConnection()
			with mysql.connection():
				with mysql.session() as session:
					session.execute("SELECT 1").fetchone()
					result.message = "No MySQL issues found."
					result.check_status = CheckStatus.OK
			self.add_partial_checks(MysqlConfigurationCheck())
		except (OperationalError, MySQLdbOperationalError) as err:
			# result.message = f"Could not connect to MySQL Server: {str(err)}"
			error_str = str(err).split("\n", 1)[0]
			match = re.search(r"\((\d+),\s+(\S.*)\)", error_str)
			if match:
				error_str = match.group(1) + " - " + match.group(2).strip("'").replace("\\'", "'")
			result.message = f"Could not connect to MySQL Server: {error_str}"
			result.check_status = CheckStatus.ERROR
		return result


@dataclass()
class UniqueHardwareAddressesCheck(Check):
	id: str = "unique_hardware_addresses"
	name: str = "Unique Hardware Addresses"
	description: str = "Check if all hardware addresses are unique"
	documentation: str = """
		## Check Unique Hardware Addresses

		Checks whether all hardware addresses are unique if unique_hardware_addresses is enabled.
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="All hardware addresses are unique.",
			check_status=CheckStatus.OK,
		)
		mysql = MySQLConnection()
		if not mysql.unique_hardware_addresses:
			result.message = "Unique hardware addresses check is disabled."
			return result
		with mysql.connection():
			with mysql.session() as session:
				res = session.execute(
					"""
					SELECT
						COUNT(DISTINCT IF(h.hardwareAddress = "", NULL, h.hardwareAddress)),
						SUM(IF(IFNULL(h.hardwareAddress, "") = "", 1, 0)),
						SUM(IF(IFNULL(h.hardwareAddress, "") = "", 0, 1)),
						COUNT(*)
					FROM
						HOST AS h
					"""
				).fetchone()
				distinct_values = int(res[0])
				empty_values = int(res[1])
				non_empty_values = int(res[2])
				total_values = int(res[3])

				logger.debug(
					"Unique hardware addresses: distinct_values=%d empty_values=%d non_empty_values=%d total_values=%d",
					distinct_values,
					empty_values,
					non_empty_values,
					total_values,
				)
				if non_empty_values != distinct_values:
					result.message = "Some hardware addresses are not unique."
					result.check_status = CheckStatus.ERROR

				result.details = {
					"distinct_values": distinct_values,
					"empty_values": empty_values,
					"non_empty_values": non_empty_values,
					"total_values": total_values,
				}

		return result


mysql_check = MysqlCheck()
unique_hardware_addresses_check = UniqueHardwareAddressesCheck()
check_manager.register(mysql_check, unique_hardware_addresses_check)
