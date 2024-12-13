# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check backup
"""

from dataclasses import dataclass
from datetime import datetime

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.check.utils import get_enabled_hosts

__all__ = ["LastSeenCheck"]


MAX_DAYS = 30


@dataclass()
class LastSeenCheck(Check):
	id: str = "opsi_active_clients"
	name: str = "OPSI active Clients"
	description: str = "Checks if the clients have been seen recently."
	documentation: str = f"""
			## Check Last Seen

			Checks if the clients have been seen recently. The clients are considered up to date if they have been seen less than {MAX_DAYS} days ago.
	"""
	partial_check: bool = False

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="All Clients have been seen recently.",
			check_status=CheckStatus.OK,
			details={},
		)

		outdated_clients = set()

		backend = get_unprotected_backend()
		clients = backend.host_getObjects(type="OpsiClient")
		enabled_hosts = get_enabled_hosts()
		now = datetime.now()
		for client in clients:
			if client.id not in enabled_hosts:
				continue
			if client.lastSeen and (now - datetime.strptime(client.lastSeen, "%Y-%m-%d %H:%M:%S")).days > MAX_DAYS:
				outdated_clients.add(client.id)

		if outdated_clients:
			result.message = "Some clients have not been seen recently."
			result.check_status = CheckStatus.WARNING
			result.details = {"outdated_clients": list(outdated_clients)}

		return result


last_seen_check = LastSeenCheck()
check_manager.register(last_seen_check)
