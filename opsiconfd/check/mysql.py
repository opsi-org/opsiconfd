# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """

# from __future__ import annotations

# from opsiconfd.backend.mysql import MAX_ALLOWED_PACKET, MySQLConnection
# from opsiconfd.check.common import Check, CheckResult, CheckStatus, PartialCheckResult, exc_to_result
# from opsiconfd.logging import logger

# class MysqlConnectionCheck(Check):
# 	def check(self) -> CheckResult:
# 		result = self.result
# 		with exc_to_result(result):
# 			mysql = MySQLConnection()
# 			with mysql.connection():
# 				with mysql.session() as session:
# 					result.add_partial_result(
# 						PartialCheckResult(
# 							check_id="mysql:connection",
# 							check_name="MySQL connection",
# 							check_status=CheckStatus.OK,
# 							message="Connection to MySQL is working",
# 						)
# 					)

# 					partial_result = PartialCheckResult(
# 						check_id="mysql:configuration",
# 						check_name="MySQL configuration",
# 						check_status=CheckStatus.OK,
# 						message="MySQL configuration is OK.",
# 					)
# 					res = session.execute("SHOW VARIABLES LIKE 'max_allowed_packet'").fetchone()
# 					max_allowed_packet = int(res[1]) if res else 0
# 					partial_result.details = {"max_allowed_packet": max_allowed_packet}
# 					if max_allowed_packet < MAX_ALLOWED_PACKET:
# 						partial_result.check_status = CheckStatus.ERROR
# 						partial_result.message = (
# 							f"Configured max_allowed_packet={max_allowed_packet} is too small (should be at least {MAX_ALLOWED_PACKET})."
# 						)
# 					result.add_partial_result(partial_result)

# 					if result.check_status != CheckStatus.OK:
# 						result.message = "Some issues found with MySQL."
# 		return result

# class UniqueHardwareAddressesCheck(Check):
# 	def check(self) -> CheckResult:
# 		result = self.result
# 		mysql = MySQLConnection()
# 		if not mysql.unique_hardware_addresses:
# 			result.message = "Unique hardware addresses check is disabled."
# 			return result
# 		with mysql.connection():
# 			with mysql.session() as session:
# 				res = session.execute(
# 					"""
# 					SELECT
# 						COUNT(DISTINCT IF(h.hardwareAddress = "", NULL, h.hardwareAddress)),
# 						SUM(IF(IFNULL(h.hardwareAddress, "") = "", 1, 0)),
# 						SUM(IF(IFNULL(h.hardwareAddress, "") = "", 0, 1)),
# 						COUNT(*)
# 					FROM
# 						HOST AS h
# 					"""
# 				).fetchone()
# 				distinct_values = int(res[0])
# 				empty_values = int(res[1])
# 				non_empty_values = int(res[2])
# 				total_values = int(res[3])

# 				logger.debug(
# 					"Unique hardware addresses: distinct_values=%d empty_values=%d non_empty_values=%d total_values=%d",
# 					distinct_values,
# 					empty_values,
# 					non_empty_values,
# 					total_values,
# 				)
# 				if non_empty_values != distinct_values:
# 					result.message = "Some hardware addresses are not unique."
# 					result.check_status = CheckStatus.ERROR

# 				result.details = {
# 					"distinct_values": distinct_values,
# 					"empty_values": empty_values,
# 					"non_empty_values": non_empty_values,
# 					"total_values": total_values,
# 				}
# 		return result


# connection_docs = 	"""
# ## Check MySQL

# Checks whether the database is accessible.
# The data from the file /etc/opsi/backends/mysql.conf is used for the connection.
# If no connection can be established, this is an error.
# """

# unique_hardware_addresses_docs ="""
# ## Check Unique Hardware Addresses

# Checks whether all hardware addresses are unique if unique_hardware_addresses is enabled.
# """


# mysql_connection_check = MysqlConnectionCheck(
# 	id="mysql_connection",
# 	name="MySQL Connection",
# 	description="Check MySQL server state",
# 	documentation=connection_docs,
# 	status=CheckStatus.OK,
# 	message="No MySQL issues found.",
# 	depot_check=False,
# )

# unique_hardware_addresses_check = UniqueHardwareAddressesCheck(
# 	id="unique_hardware_addresses",
# 	name="Unique Hardware Addresses",
# 	description="Check if all hardware addresses are unique",
# 	documentation=unique_hardware_addresses_docs,
# 	status=CheckStatus.OK,
# 	message="All hardware addresses are unique.",
# 	depot_check=False,
# )
