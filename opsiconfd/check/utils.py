# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

from datetime import datetime, timezone
from typing import Iterable

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.logging import logger


def depots() -> list[str]:
	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()
	depots = backend.host_getObjects(type="OpsiDepotserver")
	return [depot.id for depot in depots]


def get_enabled_hosts(host_ids: Iterable[str] | None = None) -> set[str]:
	"""
	Returns a list of host IDs that are enabled for checks.
	If host_ids is provided, it filters the list to only include those hosts.
	"""
	backend = get_unprotected_backend()
	config_states = backend.configState_getValues(
		config_ids=["opsi.check.enabled", "opsi.check.downtime.start", "opsi.check.downtime.end"],
		object_ids=list(host_ids) if host_ids else [],
	)
	all_hosts = set(config_states)
	downtime_hosts = set()
	now = datetime.now().astimezone()
	server_timezone = now.tzinfo
	for host in all_hosts:
		downtime_end_str = (config_states[host].get("opsi.check.downtime.end") or [""])[0]
		if downtime_end_str in (None, "", "None"):
			continue
		try:
			downtime_end = datetime.fromisoformat(downtime_end_str)
			if downtime_end.tzinfo is None:
				downtime_end = downtime_end.replace(tzinfo=server_timezone)
		except ValueError:
			logger.warning("Invalid downtime end time for host %s: %s", host, downtime_end_str)
			continue

		downtime_start = datetime(year=2024, month=1, day=1, tzinfo=timezone.utc)
		downtime_start_str = (config_states[host].get("opsi.check.downtime.start") or [""])[0]
		if downtime_start_str not in (None, "", "None"):
			try:
				downtime_start = datetime.fromisoformat(downtime_start_str)
				if downtime_start.tzinfo is None:
					downtime_start = downtime_start.replace(tzinfo=server_timezone)
			except ValueError:
				logger.warning("Invalid downtime start time for host %s: %s", host, downtime_start_str)

		if downtime_start < now and downtime_end > now:
			downtime_hosts.add(host)

	return {host for host in all_hosts - downtime_hosts if (config_states[host].get("opsi.check.enabled") or [True])[0]}
