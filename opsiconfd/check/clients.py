# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check backup
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.check.utils import get_enabled_hosts

__all__ = ["LastSeenCheck"]


MAX_DAYS_INACTIVE = 30


@dataclass()
class LastSeenCheck(Check):
	id: str = "opsi_active_clients"
	name: str = "OPSI active Clients"
	description: str = "Checks if the clients have been seen recently."
	documentation: str = f"""
			## Check Last Seen

			Checks if the clients have been seen recently. The clients are considered up to date if they have been seen less than {MAX_DAYS_INACTIVE} days ago.
	"""
	partial_check: bool = False

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="All Clients have been seen recently.",
			check_status=CheckStatus.OK,
			details={},
		)

		backend = get_unprotected_backend()
		now = datetime.now()
		client_ids = backend.host_getIdents(returnType="str", type="OpsiClient", lastSeen=f"<{now - timedelta(days=MAX_DAYS_INACTIVE)}")
		outdated_clients = set(client_ids).intersection(set(get_enabled_hosts()))

		if outdated_clients:
			result.message = "Some clients have not been seen recently."
			result.check_status = CheckStatus.WARNING
			result.details = {"outdated_clients": list(outdated_clients)}

		return result


@dataclass()
class FailedClientsCheck(Check):
	id: str = "opsi_failed_clients"
	name: str = "OPSI failed Clients"
	description: str = "Check if product installation failed on clients."
	documentation: str = """
			## Check Failed Clients

		This check verifies if the product installation has failed on any clients.
		It retrieves all clients and checks their 'actionResult' status.
		If any client has a failed installation, the check will return an error status with a list of the failed client.
	"""

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No clients have action results with the status failed.",
			check_status=CheckStatus.OK,
			details={},
		)

		backend = get_unprotected_backend()
		clients = backend.host_getObjects(type="OpsiClient")
		enabled_hosts = get_enabled_hosts()
		failed_clients = set()
		for client in clients:
			if client.id not in enabled_hosts:
				continue
			if backend.productOnClient_getObjects(clientId=client.id, actionResult="failed"):
				failed_clients.add(client.id)

		if failed_clients:
			result.message = "Some clients have action results with the status failed."
			result.check_status = CheckStatus.ERROR
			result.details = {"failed_clients": list(failed_clients)}

		return result


last_seen_check = LastSeenCheck()
failed_clients_check = FailedClientsCheck()
check_manager.register(last_seen_check, failed_clients_check)
