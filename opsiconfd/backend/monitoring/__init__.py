# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.monitoring

Integration of external monitoring systems (e.g. checkmk).
Currently only the management of downtimes is supported.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from opsi.exception import BackendConfigurationError
from opsi.opsi.service.model.type import to_bool

DEFAULT_COMMENT_PREFIX = "[OPSI]"


@dataclass(frozen=True, kw_only=True, slots=True)
class MonitoringConfig:
	"""
	Configuration of the monitoring system integration.

	Attributes:
		enabled: Whether the integration is enabled.
		type: Type of the monitoring system (currently only "checkmk").
		url: Base URL of the monitoring system (for checkmk including the site name).
		api_version: Version of the REST API to use.
		username: User name used to authenticate at the monitoring system.
		secret: Secret (password / automation secret) of the user.
		verify_ssl: True / False or path to a CA bundle.
		timeout: Request timeout in seconds.
		max_downtime_duration: Maximum allowed duration of a downtime in seconds.
		comment_prefix: Prefix identifying downtimes created by opsi.
	"""

	enabled: bool = False
	type: str = "checkmk"
	url: str = ""
	api_version: str = "1.0"
	username: str = ""
	secret: str = field(default="", repr=False)
	verify_ssl: bool | str = True
	timeout: float = 10.0
	max_downtime_duration: int = 14400
	comment_prefix: str = DEFAULT_COMMENT_PREFIX

	@classmethod
	def from_dict(cls, data: dict[str, Any]) -> MonitoringConfig:
		"""
		Create a configuration from the content of the config file.

		Args:
			data: Dictionary with camelCase keys as used in monitoring.conf.

		Returns:
			The configuration.
		"""
		verify_ssl = data.get("verifySsl", True)
		if not isinstance(verify_ssl, str):
			verify_ssl = to_bool(verify_ssl)
		return cls(
			enabled=to_bool(data.get("enabled", False)),
			type=str(data.get("type", "checkmk")).strip().lower(),
			url=str(data.get("url", "")).strip().rstrip("/"),
			api_version=str(data.get("apiVersion", "1.0")).strip(),
			username=str(data.get("username", "")),
			secret=str(data.get("secret", "")),
			verify_ssl=verify_ssl,
			timeout=float(data.get("timeout", 10)),
			max_downtime_duration=int(data.get("maxDowntimeDuration", 14400)),
			# An empty prefix would make it impossible to distinguish opsi downtimes from others
			comment_prefix=str(data.get("commentPrefix", DEFAULT_COMMENT_PREFIX)).strip() or DEFAULT_COMMENT_PREFIX,
		)


@dataclass(frozen=True, kw_only=True, slots=True)
class Downtime:
	"""
	A downtime of a host or a service.

	Attributes:
		id: ID of the downtime in the monitoring system.
		host: Host name in the monitoring system.
		service: Service description or None for a host downtime.
		start: Start of the downtime.
		end: End of the downtime.
		comment: Comment of the downtime.
		site_id: Optional ID of the monitoring site the downtime belongs to.
	"""

	id: str
	host: str
	service: str | None
	start: datetime
	end: datetime
	comment: str
	site_id: str | None = None

	def as_dict(self) -> dict[str, Any]:
		"""Return the downtime as a serializable dictionary."""
		return {
			"id": self.id,
			"host": self.host,
			"service": self.service,
			"start": self.start.isoformat(timespec="seconds"),
			"end": self.end.isoformat(timespec="seconds"),
			"comment": self.comment,
		}


class MonitoringClient(ABC):
	"""Base class for clients of monitoring systems."""

	def __init__(self, config: MonitoringConfig) -> None:
		self.config = config

	@abstractmethod
	def check_connection(self) -> dict[str, Any]:
		"""
		Check connection and authentication.

		Returns:
			Information about the monitoring system (e.g. version).

		Raises:
			BackendUnableToConnectError: If the monitoring system can not be reached.
			BackendUnaccomplishableError: If the request was rejected.
		"""

	@abstractmethod
	def get_downtimes(self, host: str) -> list[Downtime]:
		"""
		Get all downtimes of a host and its services.

		Args:
			host: Host name in the monitoring system.

		Returns:
			The downtimes.
		"""

	@abstractmethod
	def set_downtime(self, host: str, services: list[str], start: datetime, end: datetime, comment: str) -> list[Downtime]:
		"""
		Set a downtime.

		Args:
			host: Host name in the monitoring system.
			services: Service descriptions. If empty, a downtime for the whole host is set.
			start: Start of the downtime.
			end: End of the downtime.
			comment: Comment of the downtime.

		Returns:
			The created downtimes. May be empty if they could not be determined.
		"""

	@abstractmethod
	def delete_downtimes(self, downtimes: list[Downtime]) -> None:
		"""
		Delete downtimes.

		Args:
			downtimes: The downtimes to delete.
		"""


def get_monitoring_client(config: MonitoringConfig) -> MonitoringClient:
	"""
	Create a client for the configured monitoring system.

	Args:
		config: The monitoring configuration.

	Returns:
		The client.

	Raises:
		BackendConfigurationError: If the configuration is invalid.
	"""
	if not config.url:
		raise BackendConfigurationError("No url configured for monitoring system")
	if not re.match(r"^https?://", config.url):
		raise BackendConfigurationError("The url of the monitoring system must start with http:// or https://")

	if config.type == "checkmk":
		from .checkmk import CheckmkClient

		return CheckmkClient(config)

	raise BackendConfigurationError(f"Unsupported monitoring system type {config.type!r}")
