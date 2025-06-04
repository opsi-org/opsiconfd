# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from opsicommon.utils import compare_versions

from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.config import config
from opsiconfd.utils import get_requests_session


@dataclass()
class GrafanaHealth(Check):
	id: str = "grafana"
	name: str = "Grafana Health Check"
	description: str = "Check Grafana Health Check"
	documentation: str = f"""
		## {name} [{id}]

		Checks whether the Grafana server is accessible and whether the Grafana version is too old.
	"""

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="Grafana server is accessible.",
			check_status=CheckStatus.OK,
		)

		session = get_requests_session(urlparse(config.grafana_internal_url).hostname)
		res = session.get(urljoin(config.grafana_internal_url, "/api/health"), timeout=10, stream=True)

		if res.status_code != 200:
			result.check_status = CheckStatus.ERROR
			result.message = f"Cannot connect to grafana server, status code: {res.status_code}"

		res_data = res.json()
		if res_data.get("database") != "ok":
			result.check_status = CheckStatus.ERROR
			result.message = "Grafana database is not OK."

		if compare_versions(res_data.get("version", "0"), "<", "11.3.2"):
			result.check_status = CheckStatus.WARNING
			result.message = f"Grafana version is too old. Version: {res_data.get('version', 0)}"

		return result


grafana_health = GrafanaHealth()
check_manager.register(grafana_health)
