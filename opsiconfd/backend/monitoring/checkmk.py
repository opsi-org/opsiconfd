# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.monitoring.checkmk

Checkmk REST API client.
"""

from __future__ import annotations

import secrets
import ssl
import threading
import time
from datetime import UTC, datetime
from typing import Any

import httpx
from opsi.exception import (
	BackendBadValueError,
	BackendMissingDataError,
	BackendUnableToConnectError,
	BackendUnaccomplishableError,
)

from opsiconfd.logging import logger

from . import Downtime, MonitoringClient, MonitoringConfig

# The creation of a downtime does not return its id,
# so the created downtimes are looked up afterwards.
LOOKUP_ATTEMPTS = 5
LOOKUP_INTERVAL = 0.5

# Checkmk processes downtime commands sequentially.
# Concurrent write requests (a client is created per RPC call) pile up there and run into read timeouts,
# therefore all write operations of this process are serialized.
_WRITE_LOCK = threading.Lock()


def _format_time(value: datetime) -> str:
	return value.astimezone(UTC).isoformat(timespec="seconds")


def _parse_time(value: Any) -> datetime:
	parsed = datetime.fromisoformat(str(value))
	if parsed.tzinfo is None:
		parsed = parsed.replace(tzinfo=UTC)
	return parsed


class CheckmkClient(MonitoringClient):
	"""Client for the checkmk REST API."""

	def __init__(self, config: MonitoringConfig) -> None:
		super().__init__(config)
		self._verify: bool | ssl.SSLContext = True
		if isinstance(config.verify_ssl, str):
			self._verify = ssl.create_default_context(cafile=config.verify_ssl)
		else:
			self._verify = config.verify_ssl

	def _request(self, method: str, path: str, params: dict[str, Any] | None = None, json: dict[str, Any] | None = None) -> Any:
		"""
		Send a request to the REST API.

		Args:
			method: HTTP method.
			path: Path relative to the API base url.
			params: Query parameters.
			json: JSON request body.

		Returns:
			The decoded JSON response or None if the response is empty.

		Raises:
			BackendUnableToConnectError: If the server can not be reached.
			BackendMissingDataError: If the requested object was not found.
			BackendBadValueError: If the request was invalid.
			BackendUnaccomplishableError: For all other errors.
		"""
		url = f"{self.config.url}/check_mk/api/{self.config.api_version}{path}"
		headers = {
			"Authorization": f"Bearer {self.config.username} {self.config.secret}",
			"Accept": "application/json",
		}
		logger.debug("Checkmk request: %s %s", method, url)
		try:
			with httpx.Client(verify=self._verify, timeout=self.config.timeout, follow_redirects=False) as client:
				response = client.request(method, url, params=params, json=json, headers=headers)
		except httpx.HTTPError as err:
			raise BackendUnableToConnectError(f"Failed to connect to checkmk: {err}") from err

		if response.is_success:
			return response.json() if response.content else None

		detail = ""
		try:
			body = response.json()
			detail = " - ".join(str(body[key]) for key in ("title", "detail") if body.get(key))
		except ValueError, AttributeError:
			pass
		message = f"Checkmk request failed with status {response.status_code}"
		if detail:
			message = f"{message}: {detail}"

		logger.debug("%s (%s %s)", message, method, url)
		if response.status_code == 404:
			raise BackendMissingDataError(message)
		if response.status_code in (400, 422):
			raise BackendBadValueError(message)
		raise BackendUnaccomplishableError(message)

	def check_connection(self) -> dict[str, Any]:
		"""Check connection and authentication by requesting the checkmk version."""
		data = self._request("GET", "/version") or {}
		return {
			"site": data.get("site"),
			"version": (data.get("versions") or {}).get("checkmk"),
			"edition": data.get("edition"),
		}

	def get_downtimes(self, host: str) -> list[Downtime]:
		"""Get all downtimes of a host and its services."""
		data = self._request("GET", "/domain-types/downtime/collections/all", params={"host_name": host}) or {}
		downtimes = []
		for entry in data.get("value", []):
			extensions = entry.get("extensions") or {}
			try:
				downtimes.append(
					Downtime(
						id=str(extensions.get("id", entry.get("id"))),
						host=str(extensions["host_name"]),
						service=extensions.get("service_description") or None,
						start=_parse_time(extensions["start_time"]),
						end=_parse_time(extensions["end_time"]),
						comment=str(extensions.get("comment", "")),
						site_id=extensions.get("site_id") or None,
					)
				)
			except (KeyError, ValueError) as err:
				logger.warning("Ignoring unparsable checkmk downtime %r: %s", entry, err)
		return downtimes

	def set_downtime(self, host: str, services: list[str], start: datetime, end: datetime, comment: str) -> list[Downtime]:
		"""Set a host or service downtime and return the created downtimes."""
		# Unique token to identify the created downtimes, because the response does not contain ids
		comment = f"{comment} #{secrets.token_hex(4)}"
		body: dict[str, Any] = {
			"downtime_type": "service" if services else "host",
			"host_name": host,
			"start_time": _format_time(start),
			"end_time": _format_time(end),
			"comment": comment,
		}
		if services:
			body["service_descriptions"] = services
		with _WRITE_LOCK:
			self._request("POST", f"/domain-types/downtime/collections/{body['downtime_type']}", json=body)

			for attempt in range(LOOKUP_ATTEMPTS):
				downtimes = [downtime for downtime in self.get_downtimes(host) if downtime.comment == comment]
				if downtimes:
					return downtimes
				if attempt < LOOKUP_ATTEMPTS - 1:
					time.sleep(LOOKUP_INTERVAL)

		logger.warning("Could not determine the ids of the downtimes created for host %r in checkmk", host)
		return []

	def delete_downtimes(self, downtimes: list[Downtime]) -> None:
		"""Delete downtimes by id."""
		with _WRITE_LOCK:
			for downtime in downtimes:
				body: dict[str, Any] = {"delete_type": "by_id", "downtime_id": downtime.id}
				if downtime.site_id:
					body["site_id"] = downtime.site_id
				self._request("POST", "/domain-types/downtime/actions/delete/invoke", json=body)
