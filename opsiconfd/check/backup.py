# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check backup
"""

from dataclasses import dataclass

from opsiconfd.backup import BACKUP_TIME_TOLERANCE
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import config
from opsiconfd.redis import redis_client

__all__ = ["BackupCheck"]


@dataclass()
class BackupCheck(Check):
	id: str = "opsi_backup"
	name: str = "OPSI Backup"
	description: str = "Checks if the backup is up to date."
	documentation: str = """
			## Check Backup

			Checks if the backup is up to date. The backup is considered up to date if it was created less than config.max_backup_age hours ago.
	"""
	depot_check: bool = False
	partial_check: bool = False

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Backup is up to date.",
			check_status=CheckStatus.OK,
			details={},
		)

		redis = redis_client()
		backup_age = redis.ttl(f"{config.redis_key('stats')}:backup")

		if backup_age <= 0:
			result.message = f"The last successful backup was created more than {config.max_backup_age} hours ago."
			result.check_status = CheckStatus.ERROR
			return result
		if backup_age < BACKUP_TIME_TOLERANCE:
			result.message = f"The last successful backup is approaching the maximum allowed age of {config.max_backup_age} hours."
			result.check_status = CheckStatus.WARNING

		return result


backup_check = BackupCheck()
check_manager.register(backup_check)
