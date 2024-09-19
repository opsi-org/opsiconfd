# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from __future__ import annotations

from dataclasses import dataclass
from textwrap import dedent

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import DEPOT_DIR, REPOSITORY_DIR, WORKBENCH_DIR


@dataclass()
class DepotPathCheck(Check):
	id: str = "depot_path"
	name: str = "Depotserver depot_path"
	depot: str = ""
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="The configured depot corresponds to the default.",
			check_status=CheckStatus.OK,
		)
		backend = get_unprotected_backend()
		depot_obj = backend.host_getObjects(id=self.depot)[0]

		path = (depot_obj.depotLocalUrl or "").removeprefix("file://").rstrip("/")
		result.details["depot_path"] = path

		if path != DEPOT_DIR:
			result.check_status = CheckStatus.ERROR
			result.upgrade_issue = "4.3"
			result.message = (
				f"The local depot path is no longer configurable in version 4.3 and is set to {path!r} on depot {self.depot!r}."
			)

		return result


@dataclass()
class WorkbenchPathCheck(Check):
	id: str = "workbench_path"
	name: str = "Depotserver workbench_path"
	depot: str = ""
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="The configured workbench corresponds to the default.",
			check_status=CheckStatus.OK,
		)
		backend = get_unprotected_backend()
		depot_obj = backend.host_getObjects(id=self.depot)[0]

		path = (depot_obj.workbenchLocalUrl or "").removeprefix("file://").rstrip("/")
		result.details["workbench_path"] = path

		if path != WORKBENCH_DIR:
			result.check_status = CheckStatus.ERROR
			result.upgrade_issue = "4.3"
			result.message = (
				f"The local workbench path is no longer configurable in version 4.3 and is set to {path!r} on depot {self.depot!r}."
			)

		return result


@dataclass()
class RepositoryPathCheck(Check):
	id: str = "repository_path"
	name: str = "Depotserver repository_path"
	depot: str = ""
	partial_check: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="The configured repository corresponds to the default.",
			check_status=CheckStatus.OK,
		)
		backend = get_unprotected_backend()
		depot_obj = backend.host_getObjects(id=self.depot)[0]

		path = (depot_obj.repositoryLocalUrl or "").removeprefix("file://").rstrip("/")
		result.details["repository_path"] = path

		if path != REPOSITORY_DIR:
			result.check_status = CheckStatus.ERROR
			result.upgrade_issue = "4.3"
			result.message = (
				f"The local repository path is no longer configurable in version 4.3 and is set to {path!r} on depot {self.depot!r}."
			)

		return result


@dataclass()
class DepotserverCheck(Check):
	id: str = "depotservers"
	name: str = "Depotserver check"
	description: str = (
		"The opsi repository, workbench and depot must be located under /var/lib/opsi/. If this is not the case, an error will be reported."
	)
	documentation: str = dedent("""
							## Depotserver check
							The opsi repository, workbench and depot must be located under /var/lib/opsi/.
							If this is not the case, an error will be reported.
						""")
	depot_check: bool = False
	partial_check: bool = False
	depot = ""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No problems found with the depot servers.",
			check_status=CheckStatus.OK,
		)

		return result


depot_server_check = DepotserverCheck()
backend = get_unprotected_backend()
for depot in backend.host_getObjects(type="OpsiDepotserver"):
	depot_check = DepotPathCheck(id=f"depotservers:{depot.id}:depot_path", name=f"Depotserver depot path on {depot.id!r}", depot=depot.id)
	workbench_check = WorkbenchPathCheck(
		id=f"depotservers:{depot.id}:workbench", name=f"Depotserver workbench path on {depot.id!r}", depot=depot.id
	)
	repository_check = RepositoryPathCheck(
		id=f"depotservers:{depot.id}:repository", name=f"Depotserver repository path on {depot.id!r}", depot=depot.id
	)
	depot_server_check.add_partial_checks(depot_check, workbench_check, repository_check)


check_manager.register(depot_server_check)
