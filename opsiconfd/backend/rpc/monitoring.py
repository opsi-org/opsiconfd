# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.monitoring

RPC methods to manage downtimes in external monitoring systems.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from opsi.exception import (
	BackendBadValueError,
	BackendConfigurationError,
	BackendMissingDataError,
	BackendModuleDisabledError,
	BackendPermissionDeniedError,
)
from opsi.opsi.service.model.type import to_host_id, to_int, to_list

from opsiconfd.backend.monitoring import Downtime, MonitoringClient, MonitoringConfig, get_monitoring_client
from opsiconfd.config import config
from opsiconfd.logging import logger, secret_filter

from . import read_backend_config_file, rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol

MONITORING_HOST_NAME_CONFIG_ID = "monitoring.host_name"
MAX_SERVICES = 50
MAX_SERVICE_LENGTH = 256
MAX_COMMENT_LENGTH = 200
DEFAULT_COMMENT = "Maintenance"


class RPCMonitoringMixin(Protocol):
	_monitoring_config: MonitoringConfig

	def __init__(self) -> None:
		self._monitoring_config = MonitoringConfig()
		self._read_monitoring_config_file()

	def _read_monitoring_config_file(self) -> None:
		"""Read monitoring.conf. If the file is missing or invalid the integration is disabled."""
		monitoring_conf = Path(config.backend_config_dir) / "monitoring.conf"
		monitoring_config = MonitoringConfig()
		if monitoring_conf.exists():
			try:
				monitoring_config = MonitoringConfig.from_dict(read_backend_config_file(monitoring_conf, add_enabled_option=False))
			except Exception as err:
				logger.error("Failed to read monitoring config file '%s': %s", monitoring_conf, err, exc_info=True)
		if monitoring_config.secret:
			secret_filter.add_secrets(monitoring_config.secret)
		self._monitoring_config = monitoring_config

	def _monitoring_get_client(self: BackendProtocol) -> MonitoringClient:
		"""Get a client for the configured monitoring system."""
		self._assert_module("monitoring")
		if not self._monitoring_config.enabled:
			raise BackendConfigurationError("The monitoring integration is not enabled")
		return get_monitoring_client(self._monitoring_config)

	def _monitoring_resolve_host(self: BackendProtocol, host_id: str | None) -> tuple[str, str]:
		"""
		Determine the opsi host and the name of the host in the monitoring system.

		Clients may only act on their own host.

		Args:
			host_id: Optional opsi host id.

		Returns:
			Tuple of opsi host id and monitoring host name.

		Raises:
			BackendPermissionDeniedError: If a client requests another host.
			BackendBadValueError: If no host id was given and the caller is not a client.
			BackendMissingDataError: If the host does not exist.
		"""
		client_id = self._get_client_id()
		if client_id:
			if host_id and to_host_id(host_id) != client_id:
				raise BackendPermissionDeniedError("Clients can only manage downtimes of their own host")
			host_id = client_id
		else:
			if not host_id:
				raise BackendBadValueError("Parameter hostId is required")
			host_id = to_host_id(host_id)
			if not self.host_getIdents(returnType="str", id=host_id):
				raise BackendMissingDataError(f"Host {host_id!r} not found")

		monitoring_host = host_id
		# Only administrators are allowed to write this config state, see configState_* methods
		for config_state in self._configState_getObjects(configId=MONITORING_HOST_NAME_CONFIG_ID, objectId=[host_id]):
			if config_state.values and config_state.values[0] and str(config_state.values[0]).strip():
				monitoring_host = str(config_state.values[0]).strip()
		return host_id, monitoring_host

	def _monitoring_check_services(self, services: list[str] | str | None) -> list[str]:
		"""Validate and normalize a list of service descriptions."""
		if not services:
			return []
		result: list[str] = []
		for service in to_list(services):
			service = str(service).strip()
			if not service or len(service) > MAX_SERVICE_LENGTH or not service.isprintable():
				raise BackendBadValueError("Invalid service description")
			if service not in result:
				result.append(service)
		if len(result) > MAX_SERVICES:
			raise BackendBadValueError(f"Too many services (maximum is {MAX_SERVICES})")
		return result

	def _monitoring_select_downtimes(
		self: BackendProtocol,
		client: MonitoringClient,
		monitoring_host: str,
		services: list[str],
		downtime_ids: set[str],
	) -> list[Downtime]:
		"""Select the opsi downtimes of a host. Downtimes not created by opsi are never selected."""
		prefix = self._monitoring_config.comment_prefix
		selected = []
		for downtime in client.get_downtimes(monitoring_host):
			if downtime.host != monitoring_host or not downtime.comment.startswith(prefix):
				continue
			if services and downtime.service not in services:
				continue
			if downtime_ids and downtime.id not in downtime_ids:
				continue
			selected.append(downtime)
		return selected

	@rpc_method
	def monitoring_getInfo(self: BackendProtocol) -> dict[str, Any]:
		"""
		Get information about the monitoring integration.

		:return: Dictionary with the keys `enabled`, `type` and `maxDowntimeDuration` (seconds).
		"""
		enabled = self._monitoring_config.enabled
		if enabled:
			try:
				self._assert_module("monitoring")
			except BackendModuleDisabledError:
				enabled = False
		return {
			"enabled": enabled,
			"type": self._monitoring_config.type,
			"maxDowntimeDuration": self._monitoring_config.max_downtime_duration,
		}

	@rpc_method
	def monitoring_checkConnection(self: BackendProtocol) -> dict[str, Any]:
		"""
		Check the connection and authentication to the monitoring system.

		:return: Information about the monitoring system.
		"""
		return self._monitoring_get_client().check_connection()

	@rpc_method
	def monitoring_setDowntime(
		self: BackendProtocol,
		duration: int,
		comment: str | None = None,
		services: list[str] | None = None,
		hostId: str | None = None,
	) -> dict[str, Any]:
		"""
		Set a downtime for a host or for services of a host in the monitoring system.

		The downtime ends automatically after `duration` seconds.

		:param duration: Duration of the downtime in seconds.
		:param comment: Comment for the downtime.
		:param services: Service descriptions. If empty, the whole host is set to downtime.
		:param hostId: Opsi host id. Clients can only set downtimes for themselves, for all other callers the parameter is required.
		:return: Dictionary with the keys `hostId`, `monitoringHost`, `services`, `start`, `end` and `downtimeIds`.
		"""
		client = self._monitoring_get_client()
		host_id, monitoring_host = self._monitoring_resolve_host(hostId)
		services_list = self._monitoring_check_services(services)

		duration = to_int(duration)
		max_duration = self._monitoring_config.max_downtime_duration
		if duration < 1 or duration > max_duration:
			raise BackendBadValueError(f"Duration must be between 1 and {max_duration} seconds")

		comment_text = " ".join(str(comment or "").split())[:MAX_COMMENT_LENGTH] or DEFAULT_COMMENT
		start = datetime.now(UTC).replace(microsecond=0)
		end = start + timedelta(seconds=duration)

		downtimes = client.set_downtime(
			host=monitoring_host,
			services=services_list,
			start=start,
			end=end,
			comment=f"{self._monitoring_config.comment_prefix} {comment_text}",
		)
		downtime_ids = [downtime.id for downtime in downtimes]
		logger.info(
			"Set downtime for host %r (monitoring host %r, services %r) until %s, downtime ids: %r",
			host_id,
			monitoring_host,
			services_list,
			end.isoformat(),
			downtime_ids,
		)
		return {
			"hostId": host_id,
			"monitoringHost": monitoring_host,
			"services": services_list,
			"start": start.isoformat(),
			"end": end.isoformat(),
			"downtimeIds": downtime_ids,
		}

	@rpc_method
	def monitoring_removeDowntime(
		self: BackendProtocol,
		downtimeIds: list[str] | None = None,
		services: list[str] | None = None,
		hostId: str | None = None,
	) -> dict[str, Any]:
		"""
		Remove downtimes set by opsi for a host in the monitoring system.

		Downtimes which were not created by opsi are never removed.
		Without `downtimeIds` and `services` all opsi downtimes of the host are removed.

		:param downtimeIds: Only remove downtimes with these ids.
		:param services: Only remove downtimes of these services.
		:param hostId: Opsi host id. Clients can only remove downtimes of themselves, for all other callers the parameter is required.
		:return: Dictionary with the keys `hostId`, `monitoringHost` and `removed` (number of removed downtimes).
		"""
		client = self._monitoring_get_client()
		host_id, monitoring_host = self._monitoring_resolve_host(hostId)
		services_list = self._monitoring_check_services(services)
		downtime_ids = {str(downtime_id) for downtime_id in to_list(downtimeIds or [])}

		downtimes = self._monitoring_select_downtimes(client, monitoring_host, services_list, downtime_ids)
		if downtimes:
			client.delete_downtimes(downtimes)
		logger.info(
			"Removed downtimes of host %r (monitoring host %r, services %r): %r",
			host_id,
			monitoring_host,
			services_list,
			[downtime.id for downtime in downtimes],
		)
		return {"hostId": host_id, "monitoringHost": monitoring_host, "removed": len(downtimes)}

	@rpc_method
	def monitoring_getDowntimes(
		self: BackendProtocol,
		services: list[str] | None = None,
		hostId: str | None = None,
	) -> list[dict[str, Any]]:
		"""
		Get the downtimes set by opsi for a host in the monitoring system.

		:param services: Only return downtimes of these services.
		:param hostId: Opsi host id. Clients can only get downtimes of themselves, for all other callers the parameter is required.
		:return: List of dictionaries with the keys `id`, `host`, `service`, `start`, `end` and `comment`.
		"""
		client = self._monitoring_get_client()
		_, monitoring_host = self._monitoring_resolve_host(hostId)
		services_list = self._monitoring_check_services(services)
		return [downtime.as_dict() for downtime in self._monitoring_select_downtimes(client, monitoring_host, services_list, set())]
