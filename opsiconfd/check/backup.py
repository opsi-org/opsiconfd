# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check backup
"""

from dataclasses import dataclass

from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import config
from opsiconfd.redis import redis_client

__all__ = ["BackupCheck"]


@dataclass()
class BackupCheck(Check):
	# doc string?
	id: str = "opsi_backup"
	name: str = "OPSI backup"
	description: str = "Checks if the backup is up to date."
	# id: str = field(default="opsi_backup")
	# name: str = field(default="OPSI backup")
	# description: str = field(default="Checks if the backup is up to date.")
	# documentation: str = field(
	# 	default=dedent("""
	# 		## Check Backup

	# 		Checks if the backup is up to date. The backup is considered up to date if it was created less than config.max_backup_age hours ago.
	# """)
	# )

	def check(self) -> CheckResult:
		# result = self.result
		# Todo
		result = CheckResult(
			check=self,
			message="No check function defined",
			check_status=CheckStatus.ERROR,
		)
		redis = redis_client()
		backup = redis.get(f"{config.redis_key('stats')}:backup")
		if backup is None:
			result.message = f"The last successful backup was created more than {config.max_backup_age} hours ago."
			result.check_status = CheckStatus.ERROR
		return result


backup_check = BackupCheck()
check_manager.register(backup_check)
print("health check:", id(check_manager))
