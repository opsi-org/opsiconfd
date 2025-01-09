# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check worker
# """
from datetime import datetime
from dataclasses import dataclass
from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import config




MAX_DAYS_INACTIVE = 30

@dataclass()
class WorkerCapacityCheck(Check):
	id: str = "opsi_worker_capacity"
	name: str = "OPSI Worker Capacity"
	description: str = "Checks if there are enough workers for the currently active clients."
	documentation: str = """
		## Check Worker Capacity

		Checks if there are enough workers for the currently active clients.
		The clients are considered up to date if they have been seen less than {MAX_DAYS_INACTIVE} days ago.
		Warns if there are more than 600 clients per worker and errors if there are more than 1000 clients per worker.
	"""
	partial_check: bool = False

	def _check(self) -> CheckResult:
		now = datetime.now()
		worker_count = config.workers
		backend = get_unprotected_backend()
		clients = backend.host_getObjects(type="OpsiClient")
		for client in clients:
			if client.lastSeen and (now - datetime.strptime(client.lastSeen, "%Y-%m-%d %H:%M:%S")).days > MAX_DAYS_INACTIVE:
				clients.remove(client)

		active_clients = len(clients)
		result = CheckResult(
			check=self,
			message=f"There are enough workers ({worker_count}) for the currently active clients ({active_clients}).",
			check_status=CheckStatus.OK,
			details={},
		)

		# Warning if more than 600 clients perworker
		if active_clients // worker_count > 600:
			result.message = f"There are not enough workers ({worker_count}) for the currently active clients ({active_clients})."
			result.check_status = CheckStatus.WARNING
		# Error if more than 1000 clients per worker
		if active_clients // worker_count > 1000:
			result.message = f"There are not enough workers ({worker_count}) for the currently active clients ({active_clients})."
			result.check_status = CheckStatus.ERROR


		return result

opsi_worker_capacity = WorkerCapacityCheck()
check_manager.register(opsi_worker_capacity)