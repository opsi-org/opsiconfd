# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.extender
"""

from __future__ import annotations

import socket
import threading
from ipaddress import IPv6Address, ip_address
from subprocess import CalledProcessError, run
from time import sleep
from typing import TYPE_CHECKING, Protocol

from opsicommon.exceptions import BackendIOError  # type: ignore[import]
from opsicommon.objects import ConfigState, Host  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceHostIdList,
	forceList,
	forceObjectClass,
)

from opsiconfd.dhcpd import (  # type: ignore[import]
	DHCPDControlConfig,
	dhcpd_lock,
	get_dhcpd_control_config,
)
from opsiconfd.logging import logger

from . import backend_event, rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class ReloadThread(threading.Thread):
	"""This class implements a thread regularly reloading the dhcpd.conf file."""

	def __init__(self, reload_config_command: list[str]) -> None:
		threading.Thread.__init__(self)
		self.daemon = True
		self._reload_config_command = reload_config_command
		self._reload_event = threading.Event()
		self._is_reloading = False
		self._wait_after_reload = 4.0

	@property
	def is_busy(self) -> bool:
		return self._is_reloading or self._reload_event.is_set()

	def trigger_reload(self) -> None:
		"""Explicitely call a config file reload."""
		logger.debug("Reload triggered")
		if not self._reload_event.is_set():
			self._reload_event.set()

	def run(self) -> None:
		while True:
			if self._reload_event.wait(self._wait_after_reload):
				with dhcpd_lock("config_reload"):
					self._is_reloading = True
					self._reload_event.clear()
					try:
						logger.notice("Reloading dhcpd config using command: '%s'", self._reload_config_command)
						run(
							self._reload_config_command,
							shell=False,
							check=True,
							capture_output=True,
							text=True,
							encoding="utf-8",
							timeout=5,
						)
					except CalledProcessError as err:
						logger.error("Failed to reload dhcpd config: %s", err.output)
					self._is_reloading = False


class RPCDHCPDControlMixin(Protocol):  # pylint: disable=too-many-instance-attributes
	_dhcpd_control_config: DHCPDControlConfig
	_dhcpd_control_reload_thread: ReloadThread | None

	def __init__(self) -> None:
		self._dhcpd_control_config = get_dhcpd_control_config()
		self._dhcpd_control_reload_thread: ReloadThread | None = None

	def _dhcpd_control_reload_config(self) -> None:
		get_dhcpd_control_config.cache_clear()
		self._dhcpd_control_config = get_dhcpd_control_config()

	@backend_event("shutdown")
	def _dhcpd_control_shutdown(self) -> None:
		if self._dhcpd_control_reload_thread and self._dhcpd_control_reload_thread.is_busy:
			logger.info("Waiting for reload thread")
			for _ in range(3):
				if self._dhcpd_control_reload_thread.is_busy:
					sleep(1)

	def _dhcpd_control_start_reload_thread(self) -> None:
		self._dhcpd_control_reload_thread = ReloadThread(self._dhcpd_control_config.reload_config_command)
		self._dhcpd_control_reload_thread.daemon = True
		self._dhcpd_control_reload_thread.start()

	def _dhcpd_control_trigger_reload(self) -> None:
		if not self._dhcpd_control_reload_thread:
			self._dhcpd_control_start_reload_thread()
		if self._dhcpd_control_reload_thread:
			self._dhcpd_control_reload_thread.trigger_reload()

	def dhcpd_control_hosts_updated(self: BackendProtocol, host_ids: list[str]) -> None:
		if not self._dhcpd_control_config.enabled or not self.events_enabled:
			return

		logger.debug("dhcpd_control_hosts_updated: %s", host_ids)
		deleted_host_ids: list[str] = []
		for host in self.host_getObjects(type="OpsiClient", id=forceHostIdList(host_ids)):
			if not host.hardwareAddress:
				deleted_host_ids.append(host.id)
				continue

			if self._dhcpd_control_config.dhcpd_on_depot:
				responsible_depot_id = self._get_responsible_depot_id(host.id)
				if responsible_depot_id and responsible_depot_id != self._depot_id:
					logger.info("Not responsible for client '%s', forwarding request to depot '%s'", host.id, responsible_depot_id)
					self._execute_rpc_on_depot(depot_id=responsible_depot_id, method="dhcpd_updateHost", params=[host])
					continue

			self._dhcpd_updateHost(host)

		if deleted_host_ids:
			self.dhcpd_control_hosts_deleted(deleted_host_ids)

	def dhcpd_control_hosts_deleted(self: BackendProtocol, host_ids: list[str]) -> None:
		if not self._dhcpd_control_config.enabled or not self.events_enabled:
			return
		for host_id in forceHostIdList(host_ids):
			if self._dhcpd_control_config.dhcpd_on_depot:
				# Call dhcpd_deleteHost on all non local depots
				depot_ids = [did for did in self.host_getIdents(returnType="str", type="OpsiDepotserver") if did != self._depot_id]
				logger.info("Forwarding request to depots: %s", depot_ids)
				for depot_id in depot_ids:
					self._execute_rpc_on_depot(depot_id=depot_id, method="dhcpd_deleteHost", params=[host_id])

			self._dhcpd_deleteHost(host_id)

	def dhcpd_control_config_states_updated(
		self: BackendProtocol, config_states: list[dict] | list[ConfigState] | dict | ConfigState
	) -> None:
		if not self._dhcpd_control_config.enabled or not self.events_enabled:
			return
		object_ids = set()
		for config_state in forceList(config_states):
			if isinstance(config_state, ConfigState):
				if config_state.configId != "clientconfig.depot.id":
					continue
				if config_state.objectId:
					object_ids.add(config_state.objectId)
			else:
				if config_state.get("configId") != "clientconfig.depot.id":
					continue
				object_id = config_state.get("objectId")
				if object_id:
					object_ids.add(object_id)
		if object_ids:
			self.dhcpd_control_hosts_updated(list(object_ids))

	@rpc_method
	def dhcpd_updateHost(self: BackendProtocol, host: Host) -> None:  # pylint: disable=invalid-name,too-many-branches
		self._dhcpd_updateHost(host)

	def _dhcpd_updateHost(self: BackendProtocol, host: Host) -> None:  # pylint: disable=invalid-name,too-many-branches,too-many-statements
		host = forceObjectClass(host, Host)

		if not host.hardwareAddress:
			logger.warning("Cannot update dhcpd configuration for client %s: hardware address unknown", host)
			return

		hostname = host.id.split(".", 1)[0]
		host_ip_address = host.ipAddress

		current_host_params: dict[str, str | bool] | None = None
		with dhcpd_lock("config_read"):
			self._dhcpd_control_config.dhcpd_config_file.parse()
			current_host_params = self._dhcpd_control_config.dhcpd_config_file.get_host(hostname, inherit="global")

		if not host_ip_address:
			try:
				logger.info("IP addess of client %s unknown, trying to get host by name", host)
				host_ip_address = socket.gethostbyname(host.id)
				logger.info("Client fqdn resolved to %s", host_ip_address)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Failed to get IP by hostname: %s", err)
				if current_host_params:
					logger.debug("Trying to use address for %s from existing DHCP configuration.", hostname)

					if current_host_params.get("fixed-address"):
						host_ip_address = str(current_host_params["fixed-address"])
					else:
						raise BackendIOError(
							f"Cannot update dhcpd configuration for client {host.id}: "
							"ip address unknown and failed to get ip address from DHCP configuration file."
						) from err
				else:
					raise BackendIOError(
						f"Cannot update dhcpd configuration for client {host.id}: ip address unknown and failed to get host by name"
					) from err

		fixed_address = host_ip_address
		if self._dhcpd_control_config.fixed_address_format == "FQDN":
			fixed_address = host.id
		else:
			ipa = ip_address(fixed_address)
			if isinstance(ipa, IPv6Address):
				logger.debug("Not updating dhcpd configuration for client %r, got IPv6 address %s", host.id, fixed_address)
				return
			fixed_address = ipa.exploded

		parameters = self._dhcpd_control_config.default_client_parameters.copy()
		if not self._dhcpd_control_config.dhcpd_on_depot:
			try:
				depot_id = self._get_responsible_depot_id(host.id)
				if depot_id:
					depot = self.host_getObjects(id=depot_id)[0]
					if depot.ipAddress:
						parameters["next-server"] = depot.ipAddress
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to get depot info: %s", err, exc_info=True)

		if current_host_params:
			if (
				(str(current_host_params.get("hardware", " ")).split(" ")[1] == host.hardwareAddress)
				and (current_host_params.get("fixed-address") == fixed_address)
				and (current_host_params.get("next-server") == parameters.get("next-server"))
			):
				logger.debug("DHCPD config of host %r unchanged, no need to update config file", host.id)
				return
			logger.info(
				"DHCPD config of host %r changed, updating config file (%r, %r, %r, %r)",
				host.id,
				current_host_params,
				host.hardwareAddress,
				fixed_address,
				parameters.get("next-server"),
			)

		with dhcpd_lock("config_update"):
			try:
				self._dhcpd_control_config.dhcpd_config_file.parse()
				self._dhcpd_control_config.dhcpd_config_file.add_host(
					hostname=hostname,
					hardware_address=host.hardwareAddress,
					ip_address=host_ip_address,
					fixed_address=fixed_address,
					parameters=parameters,
				)
				self._dhcpd_control_config.dhcpd_config_file.generate()
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)

		self._dhcpd_control_trigger_reload()

	@rpc_method
	def dhcpd_deleteHost(self: BackendProtocol, host_id: str) -> None:  # pylint: disable=invalid-name
		self._dhcpd_deleteHost(host_id)

	def _dhcpd_deleteHost(self: BackendProtocol, host_id: str) -> None:  # pylint: disable=invalid-name
		with dhcpd_lock("config_update"):
			try:
				self._dhcpd_control_config.dhcpd_config_file.parse()
				hostname = host_id.split(".", 1)[0]
				if not self._dhcpd_control_config.dhcpd_config_file.get_host(hostname):
					return
				self._dhcpd_control_config.dhcpd_config_file.delete_host(hostname)
				self._dhcpd_control_config.dhcpd_config_file.generate()
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)

		self._dhcpd_control_trigger_reload()
