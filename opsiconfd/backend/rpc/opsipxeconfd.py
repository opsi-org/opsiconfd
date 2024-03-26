# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.extender
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from pathlib import Path
from socket import AF_UNIX, SOCK_STREAM, socket
from threading import Lock, Thread
from time import sleep
from typing import TYPE_CHECKING, Generator, Protocol

from opsicommon.objects import ConfigState, ProductOnClient
from opsicommon.types import (
	forceBool,
	forceHostId,
	forceHostIdList,
	forceObjectClassList,
)

from opsiconfd.config import config
from opsiconfd.logging import logger

from . import backend_event, read_backend_config_file, rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


_opsipxeconfd_connection_threads: dict[str, OpsiPXEConfdConnectionThread] = {}
_opsipxeconfd_connection_threads_lock: Lock = Lock()


class OpsiPXEConfdConnection:
	def __init__(self, socket_path: str, timeout: int = 60) -> None:
		self._socket_path = socket_path
		self._timeout = int(timeout)

	@contextmanager
	def _opsipxeconfd_socket_path(self) -> Generator[socket, None, None]:
		logger.notice("Creating unix socket %r", self._socket_path)
		sock = socket(AF_UNIX, SOCK_STREAM)
		sock.settimeout(self._timeout)
		try:
			with closing(sock) as unix_sock:
				unix_sock.connect(self._socket_path)
				yield unix_sock
		except Exception as err:
			raise RuntimeError(f"Failed to connect to socket '{self._socket_path}': {err}") from err

	def send_command(self, cmd: str) -> str:
		result = ""
		with self._opsipxeconfd_socket_path() as unix_sock:
			unix_sock.send(cmd.encode("utf-8"))
			data = b""
			try:
				for part in iter(lambda: unix_sock.recv(4096), b""):
					logger.trace("Received %s", part)
					data += part
				result = data.decode("utf-8")
			except Exception as err:
				raise RuntimeError(f"Failed to receive: {err}") from err

		if "ERROR" in result:
			raise RuntimeError(f"Command '{cmd}' failed: {result}")

		return result


class OpsiPXEConfdConnectionThread(Thread):
	_DEFAULT_DELAY = 3.0

	def __init__(self, socket_path: str, client_id: str, command: str) -> None:
		Thread.__init__(self)
		self.daemon = True
		self._socket_path = socket_path
		self._client_id = client_id
		self._command = command
		self._delay = self._DEFAULT_DELAY

	def run(self) -> None:
		logger.debug("OpsiPXEConfdConnectionThread %s delaying", self._client_id)
		delay_reduction = 0.2
		while self._delay > 0:
			sleep(delay_reduction)
			self._delay -= delay_reduction

		with _opsipxeconfd_connection_threads_lock:
			try:
				logger.info("Updating pxe boot configuration for client %r", self._client_id)
				con = OpsiPXEConfdConnection(self._socket_path)
				logger.debug("Sending command %s", self._command)
				result = con.send_command(self._command)
				logger.debug("Got result %s", result)
			except Exception as err:
				logger.critical("Failed to update PXE boot configuration for client %r: %s", self._client_id, err)
			finally:
				del _opsipxeconfd_connection_threads[self._client_id]

	def update_command(self, command: str) -> None:
		self._command = command
		self._delay = self._DEFAULT_DELAY
		logger.debug("Delay reset for OpsiPXEConfdConnectionThread %s", self._client_id)


class RPCOpsiPXEConfdControlMixin(Protocol):
	_opsipxeconfd_control_enabled: bool = True
	_opsipxeconfd_control_on_depot: bool = True
	_opsipxeconfd_control_socket_path: str = "/var/run/opsipxeconfd/opsipxeconfd.socket"

	def __init__(self) -> None:
		self._opsipxeconfd_control_enabled = True
		self._opsipxeconfd_control_on_depot = True
		self._read_opsipxeconfd_control_config_file()

	def _read_opsipxeconfd_control_config_file(self) -> None:
		dhcpd_control_conf = Path(config.backend_config_dir) / "opsipxeconfd.conf"
		if not dhcpd_control_conf.exists():
			logger.error("Config file '%s' not found, opsipxeconfd control disabled", dhcpd_control_conf)
			self._opsipxeconfd_control_enabled = False
			return

		for key, val in read_backend_config_file(dhcpd_control_conf).items():
			attr = "_opsipxeconfd_control_" + "".join([f"_{c.lower()}" if c.isupper() else c for c in key])
			if attr in ("_opsipxeconfd_control_opsipxeconfd_on_depot", "_opsipxeconfd_control_enabled"):
				val = forceBool(val)

			if hasattr(self, attr):
				setattr(self, attr, val)

	@backend_event("shutdown")
	def _opsipxeconfd_shutdown(self) -> None:
		with _opsipxeconfd_connection_threads_lock:
			for update_thread in _opsipxeconfd_connection_threads.values():
				update_thread.join(3)

	def _opsipxeconfd_send_command(self: BackendProtocol, client_id: str, command: str) -> None:
		with _opsipxeconfd_connection_threads_lock:
			connection_thread = _opsipxeconfd_connection_threads.get(client_id)
			if connection_thread:
				connection_thread.update_command(command)
			else:
				connection_thread = OpsiPXEConfdConnectionThread(
					socket_path=self._opsipxeconfd_control_socket_path, client_id=client_id, command=command
				)
				_opsipxeconfd_connection_threads[client_id] = connection_thread
				connection_thread.start()

	def _update_pxe_boot_configuration(self: BackendProtocol, client_id: str) -> None:
		if not self.events_enabled:
			return

		responsible_depot_id = self._get_responsible_depot_id(client_id)
		if not responsible_depot_id:
			logger.error("Failed to get responsible depot for client %r", client_id)
			return

		if self._opsipxeconfd_control_on_depot and responsible_depot_id != self._depot_id:
			logger.info("Not responsible for client '%s', forwarding request to depot %s", client_id, responsible_depot_id)
			self._execute_rpc_on_depot(depot_id=responsible_depot_id, method="opsipxeconfd_updatePXEBootConfiguration", params=[client_id])
		else:
			self._opsipxeconfd_updatePXEBootConfiguration(client_id)

	def _delete_pxe_boot_configuration(self: BackendProtocol, client_id: str, all_depots: bool = False) -> None:
		if not self.events_enabled:
			return

		responsible_depot_id = self._get_responsible_depot_id(client_id)
		if not responsible_depot_id:
			logger.error("Failed to get responsible depot for client %r", client_id)
			return

		if self._opsipxeconfd_control_on_depot:
			depot_ids = []
			if all_depots:
				# Call opsipxeconfd_deletePXEBootConfiguration on all non local depots
				depot_ids = [did for did in self.host_getIdents(returnType="str", type="OpsiDepotserver") if did != self._depot_id]
			elif responsible_depot_id != self._depot_id:
				logger.info("Not responsible for client '%s', forwarding request to depot %s", client_id, responsible_depot_id)
				depot_ids = [responsible_depot_id]

			logger.info("Forwarding request to depots: %s", depot_ids)
			for depot_id in depot_ids:
				self._execute_rpc_on_depot(depot_id=depot_id, method="opsipxeconfd_deletePXEBootConfiguration", params=[client_id])

		if responsible_depot_id == self._depot_id or all_depots:
			self._opsipxeconfd_deletePXEBootConfiguration(client_id)

	def opsipxeconfd_hosts_updated(self: BackendProtocol, host_ids: list[str]) -> None:
		if not self._opsipxeconfd_control_enabled or not self.events_enabled:
			return

		for host_id in forceHostIdList(host_ids):
			self._update_pxe_boot_configuration(host_id)

	def opsipxeconfd_hosts_deleted(self: BackendProtocol, host_ids: list[str]) -> None:
		if not self._opsipxeconfd_control_enabled or not self.events_enabled:
			return

		for host_id in forceHostIdList(host_ids):
			self._delete_pxe_boot_configuration(host_id)

	def opsipxeconfd_product_on_clients_updated(
		self: BackendProtocol, product_on_clients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		if not self._opsipxeconfd_control_enabled or not self.events_enabled:
			return

		client_ids = set()
		for poc in forceObjectClassList(product_on_clients, ProductOnClient):
			if poc.productType == "NetbootProduct" and poc.actionRequest:
				client_ids.add(poc.clientId)

		for client_id in client_ids:
			self._update_pxe_boot_configuration(client_id)

	def opsipxeconfd_product_on_clients_deleted(
		self: BackendProtocol, product_on_clients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		if not self._opsipxeconfd_control_enabled or not self.events_enabled:
			return

		client_ids = set()
		for poc in forceObjectClassList(product_on_clients, ProductOnClient):
			if poc.productType == "NetbootProduct":
				client_ids.add(poc.clientId)

		for client_id in client_ids:
			self._update_pxe_boot_configuration(client_id)

	def opsipxeconfd_config_states_updated(
		self: BackendProtocol, config_states: list[dict] | list[ConfigState] | dict | ConfigState
	) -> None:
		if not self._opsipxeconfd_control_enabled or not self.events_enabled:
			return

		object_ids = set()
		for config_state in forceObjectClassList(config_states, ConfigState):
			if config_state.configId != "clientconfig.depot.id":
				continue
			if config_state.objectId:
				object_ids.add(config_state.objectId)

		if not object_ids:
			return

		clients = self.host_getObjects(type="OpsiClient", id=list(object_ids))
		if clients:
			for client in clients:
				self._delete_pxe_boot_configuration(client.id, all_depots=True)
			for client in clients:
				self._update_pxe_boot_configuration(client.id)

	def opsipxeconfd_config_states_deleted(
		self: BackendProtocol, config_states: list[dict] | list[ConfigState] | dict | ConfigState
	) -> None:
		self.opsipxeconfd_config_states_updated(config_states)

	@rpc_method
	def opsipxeconfd_updatePXEBootConfiguration(self: BackendProtocol, client_id: str) -> None:
		"""
		Update the boot configuration of a specific client.
		This method will relay calls to opsipxeconfd who does the handling.

		:param client_id: The client whose boot configuration should be updated.
		:param data: Collected data for opsipxeconfd.
		"""
		self._opsipxeconfd_updatePXEBootConfiguration(client_id)

	def _opsipxeconfd_updatePXEBootConfiguration(self: BackendProtocol, client_id: str) -> None:
		client_id = forceHostId(client_id)
		logger.debug("Updating PXE boot config of %s", client_id)

		command = f"update {client_id}"
		self._opsipxeconfd_send_command(client_id, command)

	@rpc_method
	def opsipxeconfd_deletePXEBootConfiguration(self: BackendProtocol, client_id: str) -> None:
		self._opsipxeconfd_deletePXEBootConfiguration(client_id)

	def _opsipxeconfd_deletePXEBootConfiguration(self: BackendProtocol, client_id: str) -> None:
		client_id = forceHostId(client_id)
		logger.debug("Deleting PXE boot config of %s", client_id)
		command = f"remove {client_id}"

		self._opsipxeconfd_send_command(client_id, command)
