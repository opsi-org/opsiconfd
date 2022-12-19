# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.extender
"""

from __future__ import annotations

import json
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path
from shlex import quote
from socket import AF_UNIX, SOCK_STREAM, socket
from threading import Lock, Thread
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Generator, Protocol

from OPSI.Util import serialize  # type: ignore[import]
from opsicommon.objects import (  # type: ignore[import]
	ConfigState,
	Host,
	OpsiClient,
	ProductOnClient,
)
from opsicommon.types import (  # type: ignore[import]
	forceBool,
	forceHostId,
	forceObjectClassList,
)

from opsiconfd.config import config
from opsiconfd.logging import logger

from . import backend_event, read_backend_config_file, rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


_opsipxeconfd_connection_threads: dict[str, OpsiPXEConfdConnectionThread] = {}
_opsipxeconfd_connection_threads_lock: Lock = Lock()


class OpsiPXEConfdConnection:  # pylint: disable=too-few-public-methods
	def __init__(self, socket_path: str, timeout: int = 10) -> None:
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
			except Exception as err:  # pylint: disable=broad-except
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
			self._delay -= delay_reduction  # pylint: disable=loop-invariant-statement

		with _opsipxeconfd_connection_threads_lock:  # pylint: disable=protected-access
			try:
				logger.info("Updating pxe boot configuration for client %r", self._client_id)
				con = OpsiPXEConfdConnection(self._socket_path)
				logger.debug("Sending command %s", self._command)
				result = con.send_command(self._command)
				logger.debug("Got result %s", result)
			except Exception as err:  # pylint: disable=broad-except
				logger.critical("Failed to update PXE boot configuration for client %r: %s", self._client_id, err)
			finally:
				del _opsipxeconfd_connection_threads[self._client_id]  # pylint: disable=protected-access

	def update_command(self, command: str) -> None:
		self._command = command
		self._delay = self._DEFAULT_DELAY
		logger.debug("Delay reset for OpsiPXEConfdConnectionThread %s", self._client_id)


class RPCOpsiPXEConfdControlMixin(Protocol):  # pylint: disable=too-many-instance-attributes,too-few-public-methods
	_opsipxeconfd_control_enabled: bool = False
	_opsipxeconfd_control_on_depot: bool = False
	_opsipxeconfd_control_socket_path: str = "/var/run/opsipxeconfd/opsipxeconfd.socket"

	def __init__(self) -> None:
		self._opsipxeconfd_control_enabled = True
		self._opsipxeconfd_control_on_depot = False
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
			for update_thread in _opsipxeconfd_connection_threads.values():  # pylint: disable=loop-global-usage
				update_thread.join(3)

	def _collect_data_for_update(  # pylint: disable=too-many-locals,too-many-branches
		self: BackendProtocol, client_id: str, depot_id: str
	) -> Any:
		logger.debug("Collecting data for opsipxeconfd...")

		try:
			host = self.host_getObjects(attributes=["hardwareAddress", "opsiHostKey", "ipAddress"], id=client_id)[0]
		except IndexError:
			logger.debug("No matching host found - fast exit.")
			return serialize({"host": None, "productOnClient": []})

		product_on_clients = self.productOnClient_getObjects(
			productType="NetbootProduct",
			client_id=client_id,
			actionRequest=["setup", "uninstall", "update", "always", "once", "custom"],
		)
		try:
			product_on_client = product_on_clients[0]
		except IndexError:
			logger.debug("No productOnClient found - fast exit.")
			return serialize({"host": host, "productOnClient": []})

		try:
			product_on_depot = self.productOnDepot_getObjects(
				productType="NetbootProduct", productId=product_on_client.productId, depotId=depot_id
			)[0]
		except IndexError:
			logger.debug("No productOnDepot found - fast exit.")
			return serialize({"host": host, "productOnClient": product_on_client, "productOnDepot": None})

		# Get the product information for the version present on
		# the depot.
		product = self.product_getObjects(
			attributes=["id", "pxeConfigTemplate"],
			type="NetbootProduct",
			id=product_on_client.productId,
			productVersion=product_on_depot.productVersion,
			packageVersion=product_on_depot.packageVersion,
		)[0]

		elilo_mode = None
		service_address = None
		bootimage_append = ""

		for config_id, values in self.configState_getValues(
			config_ids=["opsi-linux-bootimage.append", "clientconfig.configserver.url", "clientconfig.dhcpd.filename"],
			object_ids=["client_id"],
			with_defaults=True,
		)[client_id].items():
			if config_id == "clientconfig.configserver.url":
				service_address = values[0]
			elif config_id == "opsi-linux-bootimage.append":
				bootimage_append = ConfigState(configId=config_id, objectId=client_id, values=values)
			elif config_id == "clientconfig.dhcpd.filename":
				try:  # pylint: disable=loop-try-except-usage
					value = values[0]
					if "elilo" in value or "shim" in value:
						if "x86" in value:
							elilo_mode = "x86"
						else:
							elilo_mode = "x64"
				except IndexError:
					# There is no default value set and no items are present
					pass
				except Exception as err:  # pylint: disable=broad-except
					logger.debug("Failed to detect elilo setting for %s: %s", client_id, err)

		product_property_states = {
			property_id: ",".join([str(v) for v in values])
			for property_id, values in self.productPropertyState_getValues(
				product_ids=[product_on_client.productId], object_ids=[client_id], with_defaults=True
			)[client_id][product_on_client.productId].items()
		}
		logger.debug("Collected product property states: %s", product_property_states)

		backend_info = self.backend_info()
		backend_info["hostCount"] = len(self.host_getIdents(type="OpsiClient"))
		data = {
			"backendInfo": backend_info,
			"host": host,
			"productOnClient": product_on_client,
			"depotId": depot_id,
			"productOnDepot": product_on_depot,
			"elilo": elilo_mode,
			"serviceAddress": service_address,
			"product": product,
			"bootimageAppend": bootimage_append,
			"productPropertyStates": product_property_states,
		}

		data = serialize(data)
		logger.debug("Collected data for opsipxeconfd (client %r): %s", client_id, data)
		return data

	@staticmethod
	def _write_opsipxeconfd_cache_file(client_id: str, data: Any) -> Path | None:
		"""
		Save data used by opsipxeconfd to a cache file.

		:param client_id: The client for whom this data is.
		:type client_id: str
		:param data: Collected data for opsipxeconfd.
		:type data: dict
		:rtype: str
		:returns: The path of the cache file. None if no file could be written.
		"""
		directory = Path("/var/run/opsipxeconfd")
		if not directory.exists():
			directory = Path(tempfile.gettempdir()) / ".opsipxeconfd"
			directory.mkdir(mode=0o775, exist_ok=True)
		cache_file = directory / f"{client_id}.json"

		logger.trace("Writing data to '%s': %s", cache_file, data)
		try:
			cache_file.write_text(json.dumps(serialize(data)), encoding="utf-8")
			cache_file.chmod(0o640)
			return cache_file
		except (OSError, IOError) as err:
			logger.debug(err, exc_info=True)
			logger.debug("Failed to write cahce file '%s': %s", cache_file, err)
		return None

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
		if self._shutting_down:
			return

		responsible_depot_id = self._get_responsible_depot_id(client_id)
		if not responsible_depot_id:
			logger.error("Failed to get responsible depot for client %r", client_id)
			return

		try:
			data = self._collect_data_for_update(client_id, responsible_depot_id)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to collect data for opsipxeconfd (client %r): %s", client_id, err, exc_info=True)
			return

		if self._opsipxeconfd_control_on_depot and responsible_depot_id != self._depot_id:
			logger.info("Not responsible for client '%s', forwarding request to depot %s", client_id, responsible_depot_id)
			jsonrpc = self._get_depot_jsonrpc_connection(responsible_depot_id)
			jsonrpc.execute_rpc(method="opsipxeconfd_updatePXEBootConfiguration", params=[client_id, data])
		else:
			self.opsipxeconfd_updatePXEBootConfiguration(client_id, data)

	def _delete_pxe_boot_configuration(self: BackendProtocol, client_id: str, all_depots: bool = False) -> None:
		if self._shutting_down:
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
				depot_ids = [responsible_depot_id]  # pylint: disable=use-tuple-over-list

			logger.info("Forwarding request to depots: %s", depot_ids)
			for depot_id in depot_ids:
				self._get_depot_jsonrpc_connection(depot_id).execute_rpc(
					method="opsipxeconfd_deletePXEBootConfiguration", params=[client_id]
				)

		if responsible_depot_id == self._depot_id or all_depots:
			self.opsipxeconfd_deletePXEBootConfiguration(client_id)

	def opsipxeconfd_hosts_updated(self: BackendProtocol, hosts: list[dict] | list[Host] | dict | Host) -> None:
		if not self._opsipxeconfd_control_enabled or self._shutting_down:
			return

		for host in forceObjectClassList(hosts, Host):
			if not isinstance(host, OpsiClient):
				continue

			self._update_pxe_boot_configuration(host.id)

	def opsipxeconfd_hosts_deleted(self: BackendProtocol, hosts: list[dict] | list[Host] | dict | Host) -> None:
		if not self._opsipxeconfd_control_enabled or self._shutting_down:
			return

		for host in forceObjectClassList(hosts, Host):
			if not isinstance(host, OpsiClient):
				continue

			self._delete_pxe_boot_configuration(host.id)

	def opsipxeconfd_product_on_clients_updated(
		self: BackendProtocol, product_on_clients: list[dict] | list[ProductOnClient] | dict | ProductOnClient
	) -> None:
		if not self._opsipxeconfd_control_enabled or self._shutting_down:
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
		if not self._opsipxeconfd_control_enabled or self._shutting_down:
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
		if not self._opsipxeconfd_control_enabled or self._shutting_down:
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
	def opsipxeconfd_updatePXEBootConfiguration(  # pylint: disable=invalid-name
		self: BackendProtocol, client_id: str, data: Dict[str, Any] | None = None
	) -> None:
		"""
		Update the boot configuration of a specific client.
		This method will relay calls to opsipxeconfd who does the handling.

		:param client_id: The client whose boot configuration should be updated.
		:param data: Collected data for opsipxeconfd.
		"""
		client_id = forceHostId(client_id)
		logger.debug("Updating PXE boot config of %s", client_id)

		command = f"update {client_id}"
		if data:
			cache_file_path = self._write_opsipxeconfd_cache_file(client_id, data)
			if cache_file_path:
				command = f"{command} {quote(str(cache_file_path))}"

		self._opsipxeconfd_send_command(client_id, command)

	@rpc_method
	def opsipxeconfd_deletePXEBootConfiguration(self: BackendProtocol, client_id: str) -> None:  # pylint: disable=invalid-name
		client_id = forceHostId(client_id)
		logger.debug("Deleting PXE boot config of %s", client_id)
		command = f"remove {client_id}"

		self._opsipxeconfd_send_command(client_id, command)
