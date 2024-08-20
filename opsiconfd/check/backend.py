# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from __future__ import annotations

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, PartialCheckResult, exc_to_result
from opsiconfd.config import DEPOT_DIR, REPOSITORY_DIR, WORKBENCH_DIR



class DepotserverCheck(Check):
	def check(self) -> CheckResult:
		result = self.result
		with exc_to_result(result):
			backend = get_unprotected_backend()
			issues = 0
			for depot in backend.host_getObjects(type="OpsiDepotserver"):
				path = (depot.depotLocalUrl or "").removeprefix("file://").rstrip("/")
				partial_result = PartialCheckResult(
					check_id=f"depotservers:{depot.id}:depot_path",
					check_name=f"Depotserver depot_path on {depot.id!r}",
					message="The configured depot path corresponds to the default.",
					details={"path": path},
				)
				if path != DEPOT_DIR:
					issues += 1
					partial_result.check_status = CheckStatus.ERROR
					partial_result.upgrade_issue = "4.3"
					partial_result.message = (
						f"The local depot path is no longer configurable in version 4.3 and is set to {path!r} on depot {depot.id!r}."
					)
				result.add_partial_result(partial_result)

				path = (depot.repositoryLocalUrl or "").removeprefix("file://").rstrip("/")
				partial_result = PartialCheckResult(
					check_id=f"depotservers:{depot.id}:repository_path",
					check_name=f"Depotserver repository_path on {depot.id!r}",
					message="The configured repository path corresponds to the default.",
					details={"path": path},
				)
				if path != REPOSITORY_DIR:
					issues += 1
					partial_result.check_status = CheckStatus.ERROR
					partial_result.upgrade_issue = "4.3"
					partial_result.message = (
						f"The local repository path is no longer configurable in version 4.3 and is set to {path!r} on depot {depot.id!r}."
					)
				result.add_partial_result(partial_result)

				path = (depot.workbenchLocalUrl or "").removeprefix("file://").rstrip("/")
				partial_result = PartialCheckResult(
					check_id=f"depotservers:{depot.id}:workbench_path",
					check_name=f"Depotserver workbench_path on {depot.id!r}",
					message="The configured workbench path corresponds to the default.",
					details={"path": path},
				)
				if path != WORKBENCH_DIR:
					issues += 1
					partial_result.check_status = CheckStatus.ERROR
					partial_result.upgrade_issue = "4.3"
					partial_result.message = (
						f"The local workbench path is no longer configurable in version 4.3 and is set to {path!r} on depot {depot.id!r}."
					)
				result.add_partial_result(partial_result)

			if issues > 0:
				result.message = f"{issues} issues found with the depot servers."

		return result

docs = """
## Depotserver check
The opsi repository, workbench and depot must be located under /var/lib/opsi/.
If this is not the case, an error will be reported.
"""


depotserver_check = DepotserverCheck(
	id="depotservers",
	name="Depotserver check",
	description=(
		"The opsi repository, workbench and depot must be located under /var/lib/opsi/."
		"If this is not the case, an error will be reported."
	),
	documentation=docs,
	depot_check=False,
	message="No problems found with the depot servers.",
	status=CheckStatus.OK,
)

