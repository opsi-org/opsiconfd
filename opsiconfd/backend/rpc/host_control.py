# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.host_control
"""

from __future__ import annotations

import struct
import time
from contextlib import closing
from ipaddress import (
	IPv4Address,
	IPv4Network,
	IPv6Address,
	IPv6Network,
	ip_address,
	ip_network,
)
from pathlib import Path
from socket import (
	AF_INET,
	IPPROTO_UDP,
	SHUT_RDWR,
	SO_BROADCAST,
	SOCK_DGRAM,
	SOCK_STREAM,
	SOL_SOCKET,
)
from socket import error as socket_error
from socket import gethostbyname, socket
from typing import TYPE_CHECKING, Any, Dict, List, Protocol

from OPSI.Util.Thread import KillableThread  # type: ignore[import]
from opsicommon.client.jsonrpc import JSONRPCClient  # type: ignore[import]
from opsicommon.exceptions import (  # type: ignore[import]
	BackendMissingDataError,
	BackendUnaccomplishableError,
)
from opsicommon.objects import Host  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceHostId,
	forceHostIdList,
	forceInt,
	forceIpAddress,
	forceList,
)

from opsiconfd.config import config
from opsiconfd.logging import logger

from . import read_backend_config_file, rpc_method  # pylint: disable=unused-import

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RpcThread(KillableThread):  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments
		self,
		host_id: str,
		address: str,
		username: str,
		password: str,
		host_rpc_timeout: int,
		opsiclientd_port: int,
		method: str,
		params: List | None = None,
	) -> None:
		KillableThread.__init__(self)
		self.host_id = forceHostId(host_id)
		self.method = str(method)
		self.params = forceList(params or [])
		self.error: str | None = None
		self.result: Any = None
		self.started = 0.0
		self.ended = 0.0

		self.jsonrpc = JSONRPCClient(
			address=f"https://{address}:{opsiclientd_port}/opsiclientd",
			username=str(username),
			password=str(password),
			connect_timeout=max(host_rpc_timeout, 0),
			read_timeout=max(host_rpc_timeout, 0),
			connect_on_init=False,
			create_methods=False,
			retry=0,
		)

	def run(self) -> None:
		self.started = time.time()
		try:
			self.result = self.jsonrpc.execute_rpc(self.method, self.params)
		except Exception as err:  # pylint: disable=broad-except
			self.error = str(err)
		finally:
			try:
				self.jsonrpc.disconnect()
			except Exception as err:  # pylint: disable=broad-except
				logger.warning("Failed to clean up jsonrpc connection: %s", err, exc_info=True)
			self.ended = time.time()


class ConnectionThread(KillableThread):
	def __init__(self, host_id: str, address: str, host_reachable_timeout: int, opsiclientd_port: int) -> None:
		KillableThread.__init__(self)
		self.host_id = forceHostId(host_id)
		self.address = forceIpAddress(address)
		self.host_reachable_timeout = host_reachable_timeout
		self.opsiclientd_port = opsiclientd_port
		self.result = False
		self.started = 0.0
		self.ended = 0.0

	def run(self) -> None:
		self.started = time.time()
		timeout = max(self.host_reachable_timeout, 0)
		logger.info("Trying connection to '%s:%d'", self.address, self.opsiclientd_port)
		try:
			sock = socket(AF_INET, SOCK_STREAM)
			sock.settimeout(timeout)
			try:
				sock.connect((self.address, self.opsiclientd_port))
				self.result = True
				sock.shutdown(SHUT_RDWR)
			finally:
				sock.close()
		except Exception as err:  # pylint: disable=broad-except
			logger.info(err, exc_info=True)
		self.ended = time.time()


class RPCHostControlMixin(Protocol):
	_host_control_opsiclientd_port: int = 4441
	_host_control_host_rpc_timeout: int = 15
	_host_control_host_reachable_timeout: int = 3
	_host_control_resolve_host_address: bool = False
	_host_control_max_connections: int = 50
	_host_control_broadcast_addresses: dict[IPv4Network | IPv6Network, dict[IPv4Address | IPv6Address, tuple[int, ...]]] = {}

	def __init__(self) -> None:
		self._set_broadcast_addresses({"0.0.0.0/0": {"255.255.255.255": (7, 9, 12287)}})
		self._read_host_control_config_file()

	def _read_host_control_config_file(self) -> None:
		mysql_conf = Path(config.backend_config_dir) / "hostcontrol.conf"

		for key, val in read_backend_config_file(mysql_conf, add_enabled_option=False).items():
			attr = "_host_control_" + "".join([f"_{c.lower()}" if c.isupper() else c for c in key])
			if attr == "_host_control_broadcast_addresses":
				self._set_broadcast_addresses(val)
			elif hasattr(self, attr):
				setattr(self, attr, val)

	def _set_broadcast_addresses(self, value: Any) -> None:
		self._host_control_broadcast_addresses = {}
		old_format = False
		if isinstance(value, list):
			old_format = True
			# Old format <list-broadcast-addresses>
			value = {"0.0.0.0/0": {addr: [7, 9, 12287] for addr in value}}

		elif not isinstance(list(value.values())[0], dict):
			old_format = True
			# Old format <broadcast-address>: <port-list>
			value = {"0.0.0.0/0": value}

		# New format <network-address>: <broadcast-address>: <port-list>
		for network_address, broadcast_addresses in value.items():
			net = ip_network(network_address)
			self._host_control_broadcast_addresses[net] = {}
			for broadcast_address, ports in broadcast_addresses.items():
				brd = ip_address(broadcast_address)
				self._host_control_broadcast_addresses[net][brd] = tuple(  # pylint: disable=loop-invariant-statement
					forceInt(port) for port in ports
				)

		if old_format:
			logger.warning(
				"Your hostcontrol backend configuration uses an old format for broadcast addresses. "
				"Please use the following new format:\n"
				'{ "<network-address>": { "<broadcast-address>": <port-list> } }\n'
				'Example: { "0.0.0.0/0": { "255.255.255.255": [7, 9, 12287] } }'
			)

	def _get_host_address(self: BackendProtocol, host: Host) -> str:
		address = None
		if self._host_control_resolve_host_address:
			try:
				address = gethostbyname(host.id)
			except socket_error as err:
				logger.trace("Failed to lookup ip address for %s: %s", host.id, err)
		if not address:
			address = host.ipAddress
		if not address and not self._host_control_resolve_host_address:
			try:
				address = gethostbyname(host.id)
			except socket_error as err:
				raise BackendUnaccomplishableError(f"Failed to resolve ip address for host '{host.id}'") from err
		if not address:
			raise BackendUnaccomplishableError(f"Failed to get ip address for host '{host.id}'")
		return address

	def _opsiclientd_rpc(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
		self: BackendProtocol, host_ids: List[str], method: str, params: List[Any] | None = None, timeout: int | None = None
	) -> dict[str, dict[str, Any]]:
		if not host_ids:
			raise BackendMissingDataError("No matching host ids found")
		host_ids = forceHostIdList(host_ids)
		method = str(method)
		params = forceList(params or [])
		if not timeout:
			timeout = self._host_control_host_rpc_timeout
		timeout = forceInt(timeout)

		result = {}
		rpcts = []
		for host in self.host_getObjects(id=host_ids):
			try:  # pylint: disable=loop-try-except-usage
				port = self._host_control_opsiclientd_port
				try:  # pylint: disable=loop-try-except-usage
					config_states = self.configState_getObjects(configId="opsiclientd.control_server.port", objectId=host.id)
					port = int(config_states[0].values[0])
					logger.info("Using port %s for opsiclientd at %s", port, host.id)
				except IndexError:
					pass  # No values found
				except Exception as err:  # pylint: disable=broad-except
					logger.warning("Failed to read custom opsiclientd port for %s: %s", host.id, err)

				address = self._get_host_address(host)
				if ":" in address:
					# IPv6
					address = f"[{address}]"
				logger.debug("Using address '%s' for host '%s'", address, host)
				rpcts.append(
					RpcThread(
						host_id=host.id,
						address=address,
						username="",
						password=host.opsiHostKey,
						host_rpc_timeout=self._host_control_host_rpc_timeout,
						opsiclientd_port=port,
						method=method,
						params=params,
					)
				)
			except Exception as err:  # pylint: disable=broad-except
				result[host.id] = {"result": None, "error": str(err)}  # pylint: disable=loop-invariant-statement

		running_threads = 0
		while rpcts:  # pylint: disable=too-many-nested-blocks
			new_rpcts = []
			for rpct in rpcts:
				if rpct.ended:
					if rpct.error:
						logger.info("Rpc to host %s failed, error: %s", rpct.hostId, rpct.error)
						result[rpct.hostId] = {"result": None, "error": rpct.error}
					else:
						logger.info("Rpc to host %s successful, result: %s", rpct.hostId, rpct.result)
						result[rpct.hostId] = {"result": rpct.result, "error": None}
					running_threads -= 1
					continue

				if not rpct.started:
					if running_threads < self._host_control_max_connections:
						logger.debug("Starting rpc to host %s", rpct.hostId)
						rpct.start()
						running_threads += 1
				else:
					time_running = round(time.time() - rpct.started)  # pylint: disable=dotted-import-in-loop
					if time_running >= timeout + 5:  # type: ignore[operator]  # pylint: disable=loop-invariant-statement
						# thread still alive 5 seconds after timeout => kill
						logger.info(
							"Rpc to host %s (address: %s) timed out after %0.2f seconds, terminating",
							rpct.hostId,
							rpct.address,
							time_running,
						)
						result[rpct.hostId] = {
							"result": None,
							"error": f"timed out after {time_running:0.2f} seconds",  # pylint: disable=loop-invariant-statement
						}
						if not rpct.ended:
							try:  # pylint: disable=loop-try-except-usage
								rpct.terminate()
							except Exception as err:  # pylint: disable=broad-except
								logger.error("Failed to terminate rpc thread: %s", err)
						running_threads -= 1
						continue
				new_rpcts.append(rpct)
			rpcts = new_rpcts
			time.sleep(0.1)  # pylint: disable=dotted-import-in-loop

		return result

	def _get_broadcast_addresses_for_host(self, host: Host) -> Any:  # pylint: disable=inconsistent-return-statements
		if not self._host_control_broadcast_addresses:
			return []

		networks = []
		if host.ipAddress:
			ipa = ip_address(host.ipAddress)
			networks = [ipn for ipn in self._host_control_broadcast_addresses if ipa and ipa in ipn]
			if len(networks) > 1:
				# Take bets matching network by prefix length
				networks = [sorted(networks, key=lambda x: x.prefixlen, reverse=True)[0]]  # pylint: disable=use-tuple-over-list
			elif not networks:
				logger.debug("No matching ip network found for host address '%s', using all broadcasts", ipa.compressed)
				networks = list(self._host_control_broadcast_addresses)
		else:
			networks = list(self._host_control_broadcast_addresses)

		for network in networks:
			for broadcast, ports in self._host_control_broadcast_addresses[network].items():
				yield (broadcast.compressed, ports)

	@rpc_method
	def hostControl_start(self: BackendProtocol, hostIds: List[str] | None = None) -> Dict[str, Any]:  # pylint: disable=invalid-name
		"""Switches on remote computers using WOL."""
		hosts = self.host_getObjects(attributes=["hardwareAddress", "ipAddress"], id=hostIds or [])
		result = {}
		for host in hosts:
			try:  # pylint: disable=loop-try-except-usage
				if not host.hardwareAddress:
					raise BackendMissingDataError(f"Failed to get hardware address for host '{host.id}'")

				mac = host.hardwareAddress.replace(":", "")
				data = b"".join([b"FFFFFFFFFFFF", mac.encode("ascii") * 16])  # Pad the synchronization stream.

				# Split up the hex values and pack.
				payload = b""
				for i in range(0, len(data), 2):
					payload = b"".join(
						[
							payload,
							struct.pack("B", int(data[i : i + 2], 16)),  # pylint: disable=dotted-import-in-loop,memoryview-over-bytes
						]
					)

				for broadcast_address, target_ports in self._get_broadcast_addresses_for_host(host):
					logger.debug("Sending data to network broadcast %s %s [%s]", broadcast_address, target_ports, data)

					for port in target_ports:
						logger.debug("Broadcasting to port %s", port)
						with closing(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) as sock:
							sock.setsockopt(SOL_SOCKET, SO_BROADCAST, True)
							sock.sendto(payload, (broadcast_address, port))

				result[host.id] = {"result": "sent", "error": None}
			except Exception as err:  # pylint: disable=broad-except
				logger.debug(err, exc_info=True)
				result[host.id] = {"result": None, "error": str(err)}  # pylint: disable=loop-invariant-statement
		return result

	@rpc_method
	def hostControl_shutdown(self: BackendProtocol, hostIds: List[str] | None = None) -> Dict[str, Any]:  # pylint: disable=invalid-name
		if not hostIds:
			raise BackendMissingDataError("No host ids given")
		hostIds = self.host_getIdents(id=hostIds or [], returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self._opsiclientd_rpc(host_ids=hostIds, method="shutdown", params=[])

	@rpc_method
	def hostControl_reboot(self: BackendProtocol, hostIds: List[str] | None = None) -> Dict[str, Any]:  # pylint: disable=invalid-name
		if not hostIds:
			raise BackendMissingDataError("No host ids given")
		hostIds = self.host_getIdents(id=hostIds or [], returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self._opsiclientd_rpc(host_ids=hostIds, method="reboot", params=[])

	@rpc_method
	def hostControl_fireEvent(  # pylint: disable=invalid-name
		self: BackendProtocol, event: str, hostIds: List[str] | None = None  # pylint: disable=invalid-name
	) -> Dict[str, Any]:
		event = str(event)
		hostIds = self.host_getIdents(id=hostIds or [], returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self._opsiclientd_rpc(host_ids=hostIds, method="fireEvent", params=[event])

	@rpc_method
	def hostControl_showPopup(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		message: str,
		hostIds: List[str] | None = None,  # pylint: disable=invalid-name
		mode: str = "prepend",
		addTimestamp: bool = True,  # pylint: disable=invalid-name
		displaySeconds: float | None = None,  # pylint: disable=invalid-name
	) -> Dict[str, Any]:
		"""
		This rpc-call creates a popup-Window with a message on given clients.

		:param message: The message to be displayed.
		:param hostIds: A list of hosts to show the message on.
		:param mode: Where to put message in relation to previous messages (prepend or append).
		:param addTimestamp: Whether to add the current timestamp to the message.
		:param displaySeconds: Number of seconds to show the message for (default None = intinity or until manually closed).
		:return: Dictionary containing the result of the rpc-call
		"""
		message = str(message)
		hostIds = self.host_getIdents(id=hostIds or [], returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		params = [message, mode, addTimestamp]
		if displaySeconds is not None:
			params.append(forceInt(displaySeconds))
		return self._opsiclientd_rpc(host_ids=hostIds, method="showPopup", params=params)

	@rpc_method
	def hostControl_uptime(self: BackendProtocol, hostIds: List[str] | None = None) -> Dict[str, Any]:  # pylint: disable=invalid-name
		hostIds = self.host_getIdents(id=hostIds or [], returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self._opsiclientd_rpc(host_ids=hostIds, method="uptime", params=[])

	@rpc_method
	def hostControl_getActiveSessions(  # pylint: disable=invalid-name
		self: BackendProtocol, hostIds: List[str] | None = None
	) -> Dict[str, Any]:
		hostIds = self.host_getIdents(id=hostIds or [], returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self._opsiclientd_rpc(host_ids=hostIds, method="getActiveSessions", params=[])

	@rpc_method
	def hostControl_opsiclientdRpc(  # pylint: disable=invalid-name
		self: BackendProtocol,
		method: str,
		params: List[Any] | None = None,
		hostIds: List[str] | None = None,
		timeout: int | None = None,  # pylint: disable=invalid-name
	) -> Dict[str, Any]:
		hostIds = self.host_getIdents(id=hostIds or [], returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self._opsiclientd_rpc(host_ids=hostIds, method=method, params=params or [], timeout=timeout)

	@rpc_method
	def hostControl_reachable(  # pylint: disable=invalid-name,too-many-branches
		self: BackendProtocol, hostIds: List[str] | None = None, timeout: int | None = None  # pylint: disable=invalid-name
	) -> Dict[str, Any]:  # pylint: disable=too-many-branches
		hostIds = self.host_getIdents(id=hostIds or [], returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		hostIds = forceHostIdList(hostIds)

		if not timeout:
			timeout = self._host_control_host_reachable_timeout
		timeout = forceInt(timeout)

		result = {}
		threads: list[ConnectionThread] = []
		for host in self.host_getObjects(id=hostIds):
			try:  # pylint: disable=loop-try-except-usage
				address = self._get_host_address(host)
				threads.append(
					ConnectionThread(
						host_id=host.id,
						address=address,
						host_reachable_timeout=self._host_control_host_reachable_timeout,
						opsiclientd_port=self._host_control_opsiclientd_port,
					)
				)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Problem found: '%s'", err)
				result[host.id] = False

		running_threads = 0
		while threads:  # pylint: disable=too-many-nested-blocks
			new_threads = []
			for thread in threads:
				if thread.ended:
					result[thread.host_id] = thread.result
					running_threads -= 1
					continue

				if not thread.started:
					if running_threads < self._host_control_max_connections:
						logger.debug("Trying to check host reachable %s", thread.host_id)
						thread.start()
						running_threads += 1
				else:
					time_running = time.time() - thread.started  # pylint: disable=dotted-import-in-loop
					if time_running >= timeout + 5:  # type: ignore[operator]  # pylint: disable=loop-invariant-statement
						# thread still alive 5 seconds after timeout => kill
						logger.error(
							"Reachable check to host %s address %s timed out after %0.2f seconds, terminating",
							thread.host_id,
							thread.address,
							time_running,
						)
						result[thread.host_id] = False
						if not thread.ended:
							try:  # pylint: disable=loop-try-except-usage
								thread.terminate()
							except Exception as err:  # pylint: disable=broad-except
								logger.error("Failed to terminate reachable thread: %s", err)
						running_threads -= 1
						continue
				new_threads.append(thread)
			threads = new_threads
			time.sleep(0.1)  # pylint: disable=dotted-import-in-loop
		return result

	@rpc_method
	def hostControl_execute(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		command: str,
		hostIds: List[str] | None = None,  # pylint: disable=invalid-name
		waitForEnding: bool = True,  # pylint: disable=invalid-name
		captureStderr: bool = True,  # pylint: disable=invalid-name
		encoding: str | None = None,
		timeout: int = 300,
	) -> Dict[str, Any]:
		command = str(command)
		hostIds = self.host_getIdents(id=hostIds, returnType="str")
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self._opsiclientd_rpc(host_ids=hostIds, method="execute", params=[command, waitForEnding, captureStderr, encoding, timeout])

	@rpc_method(check_acl="hostControl_start")
	def hostControlSafe_start(self: BackendProtocol, hostIds: List[str] | None = None) -> Dict[str, Any]:  # pylint: disable=invalid-name
		"""Switches on remote computers using WOL."""
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_start(hostIds)

	@rpc_method(check_acl="hostControl_shutdown")
	def hostControlSafe_shutdown(self: BackendProtocol, hostIds: List[str] | None = None) -> Dict[str, Any]:  # pylint: disable=invalid-name
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_shutdown(hostIds)

	@rpc_method(check_acl="hostControl_reboot")
	def hostControlSafe_reboot(self: BackendProtocol, hostIds: List[str] | None = None) -> Dict[str, Any]:  # pylint: disable=invalid-name
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_reboot(hostIds)

	@rpc_method(check_acl="hostControl_fireEvent")
	def hostControlSafe_fireEvent(  # pylint: disable=invalid-name
		self: BackendProtocol, event: str, hostIds: List[str] | None = None
	) -> Dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_fireEvent(event, hostIds)

	@rpc_method(check_acl="hostControl_showPopup")
	def hostControlSafe_showPopup(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		message: str,
		hostIds: List[str] | None = None,
		mode: str = "prepend",
		addTimestamp: bool = True,
		displaySeconds: float = 0,
	) -> Dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_showPopup(message, hostIds, mode, addTimestamp, displaySeconds)

	@rpc_method(check_acl="hostControl_uptime")
	def hostControlSafe_uptime(self: BackendProtocol, hostIds: List[str] | None = None) -> Dict[str, Any]:  # pylint: disable=invalid-name
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_uptime(hostIds)

	@rpc_method(check_acl="hostControl_getActiveSessions")
	def hostControlSafe_getActiveSessions(  # pylint: disable=invalid-name
		self: BackendProtocol, hostIds: List[str] | None = None
	) -> Dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_getActiveSessions(hostIds)

	@rpc_method(check_acl="hostControl_opsiclientdRpc")
	def hostControlSafe_opsiclientdRpc(  # pylint: disable=invalid-name
		self: BackendProtocol, method: str, params: List | None = None, hostIds: List[str] | None = None, timeout: int | None = None
	) -> Dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_opsiclientdRpc(method, params, hostIds, timeout)

	@rpc_method(check_acl="hostControl_reachable")
	def hostControlSafe_reachable(  # pylint: disable=invalid-name
		self: BackendProtocol, hostIds: List[str] | None = None, timeout: int | None = None
	) -> Dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_reachable(hostIds, timeout)

	@rpc_method(check_acl="hostControl_execute")
	def hostControlSafe_execute(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		command: str,
		hostIds: List[str] | None = None,
		waitForEnding: bool = True,
		captureStderr: bool = True,
		encoding: str | None = None,
		timeout: int = 300,
	) -> Dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_execute(command, hostIds, waitForEnding, captureStderr, encoding, timeout)
