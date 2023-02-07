# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.extender
"""

from __future__ import annotations

import os
import socket
import sys
import threading
from contextlib import contextmanager
from fcntl import LOCK_EX, LOCK_NB, LOCK_UN, flock
from pathlib import Path
from subprocess import CalledProcessError, run
from time import sleep, time
from typing import TYPE_CHECKING, Generator, Protocol

from OPSI.System.Posix import (  # type: ignore[import]
	getDHCPDRestartCommand,
	locateDHCPDConfig,
)
from OPSI.Util.File import DHCPDConfFile  # type: ignore[import]
from opsicommon.exceptions import BackendIOError  # type: ignore[import]
from opsicommon.objects import ConfigState, Host, OpsiClient  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceBool,
	forceDict,
	forceList,
	forceObjectClass,
	forceObjectClassList,
)

from opsiconfd.config import FQDN, config
from opsiconfd.logging import logger

from . import backend_event, read_backend_config_file, rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol

WAIT_AFTER_RELOAD = 4.0


@contextmanager
def dhcpd_lock(lock_type: str = "") -> Generator[None, None, None]:
	lock_file = "/var/lock/opsi-dhcpd-lock"
	with open(lock_file, "a+", encoding="utf8") as lock_fh:
		try:
			os.chmod(lock_file, 0o666)
		except PermissionError:
			pass
		attempt = 0
		while True:
			attempt += 1
			try:
				flock(lock_fh, LOCK_EX | LOCK_NB)
				break
			except IOError:
				if attempt > 200:
					raise
				sleep(0.1)
		lock_fh.seek(0)
		lines = lock_fh.readlines()
		if len(lines) >= 100:
			lines = lines[-100:]
		lines.append(f"{time()};{os.path.basename(sys.argv[0])};{os.getpid()};{lock_type}\n")
		lock_fh.seek(0)
		lock_fh.truncate()
		lock_fh.writelines(lines)
		lock_fh.flush()
		yield None
		if lock_type == "config_reload":
			sleep(WAIT_AFTER_RELOAD)
		flock(lock_fh, LOCK_UN)
	# os.remove(lock_file)


class ReloadThread(threading.Thread):
	"""This class implements a thread regularly reloading the dhcpd.conf file."""

	def __init__(self, reload_config_command: str) -> None:
		threading.Thread.__init__(self)
		self.daemon = True
		self._reload_config_command = reload_config_command
		self._reload_event = threading.Event()
		self._is_reloading = False
		self._wait_after_reload = WAIT_AFTER_RELOAD

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
							shell=True,
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
	_dhcpd_control_enabled: bool = False
	_dhcpd_control_dhcpd_config_file: str = "/etc/dhcp/dhcpd.conf"
	_dhcpd_control_reload_config_command: str | None = None
	_dhcpd_control_fixed_address_format: str = "IP"
	_dhcpd_control_default_client_parameters: dict[str, str] = {"next-server": FQDN, "filename": "linux/pxelinux.0"}
	_dhcpd_control_dhcpd_on_depot: bool = False
	_dhcpd_control_dhcpd_conf_file: DHCPDConfFile
	_dhcpd_control_reload_thread: ReloadThread | None

	def __init__(self) -> None:
		self._dhcpd_control_enabled = False
		self._dhcpd_control_default_client_parameters = {"next-server": FQDN, "filename": "linux/pxelinux.0"}
		self._dhcpd_control_dhcpd_config_file = locateDHCPDConfig(self._dhcpd_control_dhcpd_config_file)
		self._dhcpd_control_reload_config_command = f"/usr/bin/sudo {getDHCPDRestartCommand(default='/etc/init.d/dhcp3-server restart')}"
		self._dhcpd_control_reload_thread: ReloadThread | None = None
		self._read_dhcpd_control_config_file()

	@backend_event("shutdown")
	def _dhcpd_control_shutdown(self) -> None:
		if self._dhcpd_control_reload_thread and self._dhcpd_control_reload_thread.is_busy:
			logger.info("Waiting for reload thread")
			for _ in range(3):
				if self._dhcpd_control_reload_thread.is_busy:
					sleep(1)

	def _read_dhcpd_control_config_file(self) -> None:
		dhcpd_control_conf = Path(config.backend_config_dir) / "dhcpd.conf"
		if not dhcpd_control_conf.exists():
			logger.error("Config file '%s' not found, DHCPD control disabled", dhcpd_control_conf)
			self._dhcpd_control_enabled = False
			return

		for key, val in read_backend_config_file(dhcpd_control_conf).items():
			attr = "_dhcpd_control_" + "".join([f"_{c.lower()}" if c.isupper() else c for c in key])
			if attr == "_dhcpd_control_fixed_address_format" and val not in ("IP", "FQDN"):
				logger.error("Bad value %r for fixedAddressFormat, possible values are IP and FQDN", val)
				continue

			if attr in ("_dhcpd_control_dhcpd_on_depot", "_dhcpd_control_enabled"):
				val = forceBool(val)

			if hasattr(self, attr):
				setattr(self, attr, val)

		if not self._dhcpd_control_enabled:
			return

		if os.path.exists(self._dhcpd_control_dhcpd_config_file):
			self._dhcpd_control_dhcpd_conf_file = DHCPDConfFile(self._dhcpd_control_dhcpd_config_file)
		else:
			logger.error(
				"DHCPD config file %r not found, DHCPD control disabled. "
				"DHCPD control can be disabled permanently by setting 'enabled' to False in '%s'",
				self._dhcpd_control_dhcpd_config_file,
				dhcpd_control_conf,
			)
			self._dhcpd_control_enabled = False

	def _dhcpd_control_start_reload_thread(self) -> None:
		if not self._dhcpd_control_reload_config_command:
			return
		self._dhcpd_control_reload_thread = ReloadThread(self._dhcpd_control_reload_config_command)
		self._dhcpd_control_reload_thread.daemon = True
		self._dhcpd_control_reload_thread.start()

	def _dhcpd_control_trigger_reload(self) -> None:
		if not self._dhcpd_control_reload_thread:
			self._dhcpd_control_start_reload_thread()
		if self._dhcpd_control_reload_thread:
			self._dhcpd_control_reload_thread.trigger_reload()

	def dhcpd_control_hosts_updated(self: BackendProtocol, hosts: list[dict] | list[Host] | dict | Host) -> None:
		if not self._dhcpd_control_enabled or not self._events_enabled:
			return
		hosts = forceObjectClassList(hosts, Host)
		delete_hosts: list[Host] = []
		for host in hosts:
			if not isinstance(host, OpsiClient):
				continue

			if not host.hardwareAddress:
				delete_hosts.append(host)
				continue

			if self._dhcpd_control_dhcpd_on_depot:
				responsible_depot_id = self._get_responsible_depot_id(host.id)
				if responsible_depot_id and responsible_depot_id != self._depot_id:
					logger.info("Not responsible for client '%s', forwarding request to depot '%s'", host.id, responsible_depot_id)
					self._execute_rpc_on_depot(depot_id=responsible_depot_id, method="dhcpd_updateHost", params=[host])
					continue

			self.dhcpd_updateHost(host)

		if delete_hosts:
			self.dhcpd_control_hosts_deleted(delete_hosts)

	def dhcpd_control_hosts_deleted(self: BackendProtocol, hosts: list[dict] | list[Host] | dict | Host) -> None:
		if not self._dhcpd_control_enabled or not self._events_enabled:
			return
		for client in [h for h in forceObjectClassList(hosts, Host) if isinstance(h, OpsiClient)]:
			if self._dhcpd_control_dhcpd_on_depot:
				# Call dhcpd_deleteHost on all non local depots
				depot_ids = [did for did in self.host_getIdents(returnType="str", type="OpsiDepotserver") if did != self._depot_id]
				logger.info("Forwarding request to depots: %s", depot_ids)
				for depot_id in depot_ids:
					self._execute_rpc_on_depot(depot_id=depot_id, method="dhcpd_deleteHost", params=[client])

			self.dhcpd_deleteHost(client)

	def dhcpd_control_config_states_updated(
		self: BackendProtocol, config_states: list[dict] | list[ConfigState] | dict | ConfigState
	) -> None:
		if not self._dhcpd_control_enabled or not self._events_enabled:
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
		if not object_ids:
			return

		hosts = self.host_getObjects(id=list(object_ids))
		if hosts:
			self.dhcpd_control_hosts_updated(hosts)

	@rpc_method
	def dhcpd_updateHost(self: BackendProtocol, host: Host) -> None:  # pylint: disable=invalid-name,too-many-branches
		host = forceObjectClass(host, Host)

		if not host.hardwareAddress:
			logger.warning("Cannot update dhcpd configuration for client %s: hardware address unknown", host)
			return

		hostname = host.id.split(".", 1)[0]
		ip_address = host.ipAddress
		if not ip_address:
			try:
				logger.info("IP addess of client %s unknown, trying to get host by name", host)
				ip_address = socket.gethostbyname(host.id)
				logger.info("Client fqdn resolved to %s", ip_address)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Failed to get IP by hostname: %s", err)
				with dhcpd_lock("config_read"):
					self._dhcpd_control_dhcpd_conf_file.parse()
					current_host_params = self._dhcpd_control_dhcpd_conf_file.getHost(hostname)

				if current_host_params:
					logger.debug("Trying to use address for %s from existing DHCP configuration.", hostname)

					if current_host_params.get("fixed-address"):
						ip_address = current_host_params["fixed-address"]
					else:
						raise BackendIOError(
							f"Cannot update dhcpd configuration for client {host.id}: "
							"ip address unknown and failed to get ip address from DHCP configuration file."
						) from err
				else:
					raise BackendIOError(
						f"Cannot update dhcpd configuration for client {host.id}: " "ip address unknown and failed to get host by name"
					) from err

		fixed_address = ip_address
		if self._dhcpd_control_fixed_address_format == "FQDN":
			fixed_address = host.id

		parameters = forceDict(self._dhcpd_control_default_client_parameters)
		if not self._dhcpd_control_dhcpd_on_depot:
			try:
				depot_id = self._get_responsible_depot_id(host.id)
				if depot_id:
					depot = self.host_getObjects(id=depot_id)[0]
					if depot.ipAddress:
						parameters["next-server"] = depot.ipAddress
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to get depot info: %s", err, exc_info=True)

		with dhcpd_lock("config_update"):
			try:
				self._dhcpd_control_dhcpd_conf_file.parse()
				current_host_params = self._dhcpd_control_dhcpd_conf_file.getHost(hostname)
				if (
					current_host_params
					and (current_host_params.get("hardware", " ").split(" ")[1] == host.hardwareAddress)
					and (current_host_params.get("fixed-address") == fixed_address)
					and (current_host_params.get("next-server") == parameters.get("next-server"))
				):

					logger.debug("DHCPD config of host '%s' unchanged, no need to update config file", host)
					return

				self._dhcpd_control_dhcpd_conf_file.addHost(
					hostname=hostname,
					hardwareAddress=host.hardwareAddress,
					ipAddress=ip_address,
					fixedAddress=fixed_address,
					parameters=parameters,
				)
				self._dhcpd_control_dhcpd_conf_file.generate()
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)

		self._dhcpd_control_trigger_reload()

	@rpc_method
	def dhcpd_deleteHost(self: BackendProtocol, host: Host) -> None:  # pylint: disable=invalid-name
		host = forceObjectClass(host, Host)

		with dhcpd_lock("config_update"):
			try:
				self._dhcpd_control_dhcpd_conf_file.parse()
				hostname = host.id.split(".", 1)[0]
				if not self._dhcpd_control_dhcpd_conf_file.getHost(hostname):
					return
				self._dhcpd_control_dhcpd_conf_file.deleteHost(hostname)
				self._dhcpd_control_dhcpd_conf_file.generate()
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)

		self._dhcpd_control_trigger_reload()
