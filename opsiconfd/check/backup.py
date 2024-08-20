# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check backup
"""

from opsiconfd.check.common import CheckResult, CheckStatus, Check
from opsiconfd.config import config
from opsiconfd.redis import redis_client



class BackupCheck(Check):
	def check(self) -> CheckResult:
		result = self.result
		redis = redis_client()
		backup = redis.get(f"{config.redis_key('stats')}:backup")
		if backup is None:
			result.message = f"The last successful backup was created more than {config.max_backup_age} hours ago."
			result.check_status = CheckStatus.ERROR
		return result

docs = """
## Check Backup

Checks if the backup is up to date. The backup is considered up to date if it was created less than config.max_backup_age hours ago.
"""

backup_check = BackupCheck(
	id="opsi_backup",
	name="OPSI backup",
	description="Checks if the backup is up to date.",
	documentation=docs,
	message="Backup is up to date.",
	status=CheckStatus.OK,
	depot_check=False,
)

