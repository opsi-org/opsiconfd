# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

from dataclasses import dataclass
from datetime import datetime, timedelta

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import config

MAX_DAYS_INACTIVE = 30
CLIENT_NUMBER_WARNING = 600
CLIENT_NUMBER_ERROR = 1000


@dataclass()
class WorkerCapacityCheck(Check):
	id: str = "opsi_worker_capacity"
	name: str = "OPSI Worker Capacity"
	description: str = "Checks if there are enough workers for the currently active clients."
	documentation: str = f"""
		## Check Worker Capacity

		Checks if there are enough workers for the currently active clients.
		The clients are considered up to date if they have been seen less than {MAX_DAYS_INACTIVE} days ago.
		Warns if there are more than {CLIENT_NUMBER_WARNING} clients per worker and errors if there are more than {CLIENT_NUMBER_ERROR} clients per worker.
	"""

	def _check(self) -> CheckResult:
		now = datetime.now()
		worker_count = config.workers
		backend = get_unprotected_backend()
		client_ids = backend.host_getIdents(returnType="str", type="OpsiClient", lastSeen=f">{now - timedelta(days=MAX_DAYS_INACTIVE)}")

		active_clients = len(client_ids)
		result = CheckResult(
			check=self,
			message=f"There are enough workers ({worker_count}) for the currently active clients ({active_clients}).",
			check_status=CheckStatus.OK,
			details={},
		)

		# Warning if more than CLIENT_NUMBER_WARNING clients perworker
		if active_clients // worker_count > CLIENT_NUMBER_WARNING:
			result.message = f"There are not enough workers ({worker_count}) for the currently active clients ({active_clients})."
			result.check_status = CheckStatus.WARNING
		# Error if more than CLIENT_NUMBER_ERROR clients per worker
		if active_clients // worker_count > CLIENT_NUMBER_ERROR:
			result.message = f"There are not enough workers ({worker_count}) for the currently active clients ({active_clients})."
			result.check_status = CheckStatus.ERROR

		return result


opsi_worker_capacity = WorkerCapacityCheck()
check_manager.register(opsi_worker_capacity)
