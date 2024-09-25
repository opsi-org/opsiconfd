# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.host_control
"""

from __future__ import annotations

import asyncio
import base64
import struct
import time
from ipaddress import (
	IPv4Address,
	IPv4Network,
	IPv6Address,
	IPv6Network,
	ip_address,
	ip_network,
)
from pathlib import Path
from socket import AF_INET, SHUT_RDWR, SOCK_STREAM, gethostbyname, socket
from socket import error as socket_error
from threading import Thread
from typing import TYPE_CHECKING, Any, Protocol

from OPSI.Util.Thread import KillableThread  # type: ignore[import-untyped]
from opsicommon.client.jsonrpc import JSONRPCClient
from opsicommon.exceptions import (
	BackendMissingDataError,
	BackendUnaccomplishableError,
)
from opsicommon.messagebus.message import (
	JSONRPCRequestMessage,
	JSONRPCResponseMessage,
	timestamp,
)
from opsicommon.objects import Host
from opsicommon.types import (
	forceBool,
	forceHostId,
	forceHostIdList,
	forceInt,
	forceIpAddress,
	forceList,
)
from starlette.concurrency import run_in_threadpool

from opsiconfd.config import config, get_server_role
from opsiconfd.logging import logger
from opsiconfd.messagebus import get_user_id_for_host, get_user_id_for_service_worker
from opsiconfd.messagebus.redis import (
	MessageReader,
	get_websocket_connected_users,
	send_message,
	session_channel,
)
from opsiconfd.worker import Worker

from . import read_backend_config_file, rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RpcThread(KillableThread):
	def __init__(
		self,
		host_id: str,
		address: str,
		username: str,
		password: str,
		host_rpc_timeout: int,
		opsiclientd_port: int,
		method: str,
		params: list[Any] | None = None,
	) -> None:
		KillableThread.__init__(self)
		self.host_id = forceHostId(host_id)
		self.address = str(address)
		self.method = str(method)
		self.params = forceList(params or [])
		self.error: str | None = None
		self.result: Any = None
		self.started = 0.0
		self.ended = 0.0

		self.jsonrpc = JSONRPCClient(
			address=f"https://{self.address}:{opsiclientd_port}/opsiclientd",
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
		except Exception as err:
			self.error = str(err)
		finally:
			try:
				self.jsonrpc.disconnect()
			except Exception as err:
				logger.warning("Failed to clean up jsonrpc connection: %s", err, exc_info=True)
			self.ended = time.time()


class ConnectionThread(Thread):
	def __init__(self, host_id: str, address: str, host_reachable_timeout: int, opsiclientd_port: int) -> None:
		Thread.__init__(self)
		self.daemon = True
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
		except Exception as err:
			logger.info(err, exc_info=True)
		self.ended = time.time()


class RPCHostControlMixin(Protocol):
	_host_control_opsiclientd_port: int = 4441
	_host_control_host_rpc_timeout: int = 15
	_host_control_host_reachable_timeout: int = 3
	_host_control_resolve_host_address: bool = False
	_host_control_max_connections: int = 500
	_host_control_broadcast_addresses: dict[IPv4Network | IPv6Network, dict[IPv4Address | IPv6Address, tuple[int, ...]]] = {}
	_host_control_use_messagebus: str | bool = "hybrid"

	def __init__(self) -> None:
		self._set_broadcast_addresses({"0.0.0.0/0": {"255.255.255.255": (7, 9, 12287)}})
		self._read_host_control_config_file()

	def _read_host_control_config_file(self) -> None:
		mysql_conf = Path(config.backend_config_dir) / "hostcontrol.conf"

		for key, val in read_backend_config_file(mysql_conf, add_enabled_option=False).items():
			attr = "_host_control_" + "".join([f"_{c.lower()}" if c.isupper() else c for c in key])
			if attr == "_host_control_broadcast_addresses":
				self._set_broadcast_addresses(val)
				continue

			if attr == "_host_control_resolve_host_address":
				val = forceBool(val)
			elif attr == "_host_control_use_messagebus":
				if val != "hybrid":
					val = forceBool(val)

			if hasattr(self, attr):
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
				self._host_control_broadcast_addresses[net][brd] = tuple(forceInt(port) for port in ports)

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
		else:
			address = host.ipAddress
		if not address:
			raise BackendUnaccomplishableError(f"Failed to get ip address for host '{host.id}'")
		return address

	async def _messagebus_rpc(
		self: BackendProtocol,
		client_ids: list[str],
		method: str,
		params: list[Any] | None = None,
		timeout: float | int | None = None,
		messagebus_only: bool = False,
	) -> dict[str, dict[str, Any]]:
		if not timeout:
			timeout = self._host_control_host_rpc_timeout
		timeout = float(timeout)
		connected_client_ids = [client_id async for client_id in get_websocket_connected_users(user_ids=client_ids, user_type="client")]

		result: dict[str, dict[str, Any]] = {}

		not_connected_client_ids = list(set(client_ids).difference(set(connected_client_ids)))
		if not_connected_client_ids:
			if not messagebus_only and self._host_control_use_messagebus == "hybrid":
				result = await run_in_threadpool(
					self._opsiclientd_rpc, host_ids=not_connected_client_ids, method=method, params=params, timeout=int(timeout)
				)
			else:
				for client_id in client_ids:
					if client_id not in connected_client_ids:
						result[client_id] = {"result": None, "error": "Host currently not connected to messagebus"}
						continue

		if not connected_client_ids:
			return result

		messagebus_user_id = get_user_id_for_service_worker(Worker.get_instance().id)
		rpc_id_to_client_id = {}
		async with session_channel(owner_id=messagebus_user_id) as channel:
			# ID "$" means: Only read new messages added after reader is started.
			message_reader = MessageReader(name=f"messagebus_rpc/{channel}")
			await message_reader.set_channels({channel: "$"})

			expires = timestamp(timeout)
			coros = []
			for client_id in connected_client_ids:
				jsonrpc_request = JSONRPCRequestMessage(
					sender=messagebus_user_id,
					channel=get_user_id_for_host(client_id),
					back_channel=channel,
					expires=expires,
					method=method,
					params=tuple(params or []),
				)
				rpc_id_to_client_id[jsonrpc_request.rpc_id] = client_id
				logger.debug("Sending request: %s", jsonrpc_request)
				coros.append(send_message(jsonrpc_request))
			await asyncio.gather(*coros)

			logger.debug("Waiting for JSONRPCResponseMessages (timeout=%r)")
			async for _redis_msg_id, message, _context in message_reader.get_messages(timeout=timeout):
				if not isinstance(message, JSONRPCResponseMessage) or not message.rpc_id:
					continue

				client_id = rpc_id_to_client_id.pop(message.rpc_id, "")
				if not client_id:
					continue

				logger.debug("Got response: %s", message)

				result[client_id] = {"result": message.result, "error": message.error}
				if not rpc_id_to_client_id:
					break

		error = {"result": None, "error": f"Timed out after {timeout:0.2f} seconds  while waiting for response"}
		for client_id in rpc_id_to_client_id.values():
			result[client_id] = error

		return result

	def _opsiclientd_rpc(
		self: BackendProtocol, host_ids: list[str], method: str, params: list[Any] | None = None, timeout: int | None = None
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
			try:
				port = self._host_control_opsiclientd_port
				try:
					config_states = self.configState_getObjects(configId="opsiclientd.control_server.port", objectId=host.id)
					port = int(config_states[0].values[0])
					logger.info("Using port %s for opsiclientd at %s", port, host.id)
				except IndexError:
					pass  # No values found
				except Exception as err:
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
			except Exception as err:
				result[host.id] = {"result": None, "error": str(err)}

		running_threads = 0
		while rpcts:
			new_rpcts = []
			for rpct in rpcts:
				if rpct.ended:
					if rpct.error:
						logger.info("Rpc to host %s failed, error: %s", rpct.host_id, rpct.error)
						result[rpct.host_id] = {"result": None, "error": rpct.error}
					else:
						logger.info("Rpc to host %s successful, result: %s", rpct.host_id, rpct.result)
						result[rpct.host_id] = {"result": rpct.result, "error": None}
					running_threads -= 1
					continue

				if not rpct.started:
					if running_threads < self._host_control_max_connections:
						logger.debug("Starting rpc to host %s", rpct.host_id)
						rpct.start()
						running_threads += 1
				else:
					time_running = round(time.time() - rpct.started)
					if time_running >= timeout + 5:  # type: ignore[operator]
						# thread still alive 5 seconds after timeout => kill
						logger.info(
							"Rpc to host %s (address: %s) timed out after %0.2f seconds, terminating",
							rpct.host_id,
							rpct.address,
							time_running,
						)
						result[rpct.host_id] = {
							"result": None,
							"error": f"timed out after {time_running:0.2f} seconds",
						}
						if not rpct.ended:
							try:
								rpct.terminate()
							except Exception as err:
								logger.error("Failed to terminate rpc thread: %s", err)
						running_threads -= 1
						continue
				new_rpcts.append(rpct)
			rpcts = new_rpcts
			time.sleep(0.1)

		return result

	def _get_broadcast_addresses_for_host(self, host: Host) -> Any:
		if not self._host_control_broadcast_addresses:
			return []

		networks = []
		if host.ipAddress:
			ipa = ip_address(host.ipAddress)
			networks = [ipn for ipn in self._host_control_broadcast_addresses if ipa and ipa in ipn]
			if len(networks) > 1:
				# Take best matching network by prefix length
				networks = [sorted(networks, key=lambda x: x.prefixlen, reverse=True)[0]]
			elif not networks:
				logger.debug("No matching ip network found for host address '%s', using all broadcasts", ipa.compressed)
				networks = list(self._host_control_broadcast_addresses)
		else:
			networks = list(self._host_control_broadcast_addresses)

		for network in networks:
			for broadcast, ports in self._host_control_broadcast_addresses[network].items():
				yield (broadcast.compressed, ports)

	@rpc_method
	def hostControl_start(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		"""Switches on remote computers using WOL."""
		hosts = self.host_getObjects(attributes=["hardwareAddress", "ipAddress"], id=hostIds or [])
		result = {}
		for host in hosts:
			try:
				if not host.hardwareAddress:
					raise BackendMissingDataError(f"Failed to get hardware address for host '{host.id}'")

				responsible_depot_id = self._depot_id
				if get_server_role() == "configserver":
					responsible_depot_id = self._get_responsible_depot_id(host.id) or self._depot_id
					if responsible_depot_id != self._depot_id:
						logger.info("Not responsible for client '%s', sending WOL broadcast via depot '%s'", host.id, responsible_depot_id)

				mac = host.hardwareAddress.replace(":", "")
				data = b"".join([b"FFFFFFFFFFFF", mac.encode("ascii") * 16])  # Pad the synchronization stream.

				# Split up the hex values and pack.
				payload = b""
				for i in range(0, len(data), 2):
					payload = b"".join([payload, struct.pack("B", int(data[i : i + 2], 16))])

				str_payload = base64.b64encode(payload)
				for broadcast_address, target_ports in self._get_broadcast_addresses_for_host(host):
					if responsible_depot_id != self._depot_id:
						self._execute_rpc_on_depot(
							depot_id=responsible_depot_id,
							method="network_sendBroadcast",
							params=[broadcast_address, target_ports, str_payload],
						)
					else:
						self.network_sendBroadcast(broadcast_address, target_ports, str_payload)

				result[host.id] = {"result": "sent", "error": None}
			except Exception as err:
				logger.debug(err, exc_info=True)
				result[host.id] = {"result": None, "error": str(err)}
		return result

	@rpc_method
	async def hostControl_shutdown(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No host ids given")
		hostIds = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds or [])
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")

		if self._host_control_use_messagebus:
			return await self._messagebus_rpc(client_ids=hostIds, method="shutdown", params=[])
		return await run_in_threadpool(self._opsiclientd_rpc, host_ids=hostIds, method="shutdown", params=[])

	@rpc_method
	async def hostControl_reboot(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No host ids given")
		hostIds = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds or [])
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")

		if self._host_control_use_messagebus:
			return await self._messagebus_rpc(client_ids=hostIds, method="reboot", params=[])
		return await run_in_threadpool(self._opsiclientd_rpc, host_ids=hostIds, method="reboot", params=[])

	@rpc_method
	async def hostControl_fireEvent(
		self: BackendProtocol,
		event: str,
		hostIds: list[str] | None = None,
	) -> dict[str, Any]:
		event = str(event)
		hostIds = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds or [])
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")

		if self._host_control_use_messagebus:
			return await self._messagebus_rpc(client_ids=hostIds, method="fireEvent", params=[event])
		return await run_in_threadpool(self._opsiclientd_rpc, host_ids=hostIds, method="fireEvent", params=[event])

	@rpc_method
	async def hostControl_showPopup(
		self: BackendProtocol,
		message: str,
		hostIds: list[str] | None = None,
		mode: str = "prepend",
		addTimestamp: bool = True,
		displaySeconds: float | None = None,
	) -> dict[str, Any]:
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
		hostIds = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds or [])
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		params = [message, mode, addTimestamp]
		if displaySeconds is not None:
			params.append(forceInt(displaySeconds))

		if self._host_control_use_messagebus:
			return await self._messagebus_rpc(client_ids=hostIds, method="showPopup", params=params)
		return await run_in_threadpool(self._opsiclientd_rpc, host_ids=hostIds, method="showPopup", params=params)

	@rpc_method
	async def hostControl_uptime(
		self: BackendProtocol,
		hostIds: list[str] | None = None,
	) -> dict[str, Any]:
		hostIds = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds or [])
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")

		if self._host_control_use_messagebus:
			return await self._messagebus_rpc(client_ids=hostIds, method="uptime", params=[])
		return await run_in_threadpool(self._opsiclientd_rpc, host_ids=hostIds, method="uptime", params=[])

	@rpc_method
	async def hostControl_getActiveSessions(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		hostIds = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds or [])
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")

		if self._host_control_use_messagebus:
			return await self._messagebus_rpc(client_ids=hostIds, method="getActiveSessions", params=[])
		return await run_in_threadpool(self._opsiclientd_rpc, host_ids=hostIds, method="getActiveSessions", params=[])

	@rpc_method
	async def hostControl_processActionRequests(
		self: BackendProtocol, hostIds: list[str] | None = None, productIds: list[str] | None = None
	) -> dict[str, dict[str, Any]]:
		client_ids = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds or [])
		if not client_ids:
			raise BackendMissingDataError("No matching host ids found")

		if not productIds:
			if self._host_control_use_messagebus:
				return await self._messagebus_rpc(client_ids=client_ids, method="processActionRequests", params=[])
			return await run_in_threadpool(self._opsiclientd_rpc, host_ids=client_ids, method="processActionRequests", params=[])

		result: dict[str, dict[str, Any]] = {}
		for client_id in client_ids:
			pocs = await run_in_threadpool(self.productOnClient_getObjects, clientId=[client_id], productId=productIds)
			pocs = [poc for poc in pocs if poc.actionRequest and poc.actionRequest != "none"]
			if not pocs:
				result[client_id] = {
					"result": None,
					"error": f"No product action requests set for client {client_id!r} and products {productIds!r}",
				}
				continue

			pocs = await run_in_threadpool(self.productOnClient_updateObjectsWithDependencies, productOnClients=pocs)
			product_ids = [poc.productId for poc in pocs]
			if self._host_control_use_messagebus:
				result.update(await self._messagebus_rpc(client_ids=[client_id], method="processActionRequests", params=[product_ids]))
			else:
				result.update(
					await run_in_threadpool(
						self._opsiclientd_rpc, host_ids=[client_id], method="processActionRequests", params=[product_ids]
					)
				)
		return result

	@rpc_method
	async def hostControl_opsiclientdRpc(
		self: BackendProtocol,
		method: str,
		params: list[Any] | None = None,
		hostIds: list[str] | None = None,
		timeout: int | None = None,
	) -> dict[str, Any]:
		hostIds = await run_in_threadpool(self.host_getIdents, returnType="str", type="OpsiClient", id=hostIds or [])
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")

		if self._host_control_use_messagebus:
			return await self._messagebus_rpc(client_ids=hostIds, method=method, params=params, timeout=timeout)
		return await run_in_threadpool(self._opsiclientd_rpc, host_ids=hostIds, method=method, params=params, timeout=timeout)

	@rpc_method
	async def hostControl_reachable(
		self: BackendProtocol,
		hostIds: list[str] | None = None,
		timeout: int | None = None,
	) -> dict[str, bool]:
		hostIds = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds or [])
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		client_ids: list[str] = forceHostIdList(hostIds)
		_timeout = forceInt(timeout or self._host_control_host_reachable_timeout)

		result: dict[str, bool] = {}
		if self._host_control_use_messagebus:
			connected_client_ids = [client_id async for client_id in get_websocket_connected_users(user_ids=client_ids, user_type="client")]
			result = {client_id: client_id in connected_client_ids for client_id in client_ids}
			if self._host_control_use_messagebus != "hybrid":
				return result
			client_ids = list(set(client_ids).difference(set(connected_client_ids)))
			if not client_ids:
				return result

		result.update(await run_in_threadpool(self._host_control_reachable, client_ids=client_ids, timeout=_timeout))
		return result

	def _host_control_reachable(self: BackendProtocol, client_ids: list[str], timeout: int) -> dict[str, Any]:
		result = {}
		threads: list[ConnectionThread] = []
		for host in self.host_getObjects(type="OpsiClient", id=client_ids):
			if self._shutting_down:
				return {}
			try:
				address = self._get_host_address(host)
				threads.append(
					ConnectionThread(
						host_id=host.id,
						address=address,
						host_reachable_timeout=self._host_control_host_reachable_timeout,
						opsiclientd_port=self._host_control_opsiclientd_port,
					)
				)
			except Exception as err:
				logger.debug("Problem found: '%s'", err)
				result[host.id] = False

		running_threads = 0
		while threads:
			if self._shutting_down:
				return {}
			new_threads = []
			for thread in threads:
				if thread.ended:
					result[thread.host_id] = thread.result
					running_threads -= 1
					continue
				if not thread.started and running_threads < self._host_control_max_connections:
					logger.debug("Trying to check host reachable %s", thread.host_id)
					thread.start()
					running_threads += 1
				new_threads.append(thread)
			threads = new_threads
			time.sleep(0.5)
		return result

	@rpc_method
	async def hostControl_execute(
		self: BackendProtocol,
		command: str,
		hostIds: list[str] | None = None,
		waitForEnding: bool = True,
		captureStderr: bool = True,
		encoding: str | None = None,
		timeout: int = 300,
	) -> dict[str, Any]:
		command = str(command)
		hostIds = self.host_getIdents(returnType="str", type="OpsiClient", id=hostIds)
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")

		if self._host_control_use_messagebus:
			return await self._messagebus_rpc(
				client_ids=hostIds, method="execute", params=[command, waitForEnding, captureStderr, encoding, timeout]
			)
		return await run_in_threadpool(
			self._opsiclientd_rpc, host_ids=hostIds, method="execute", params=[command, waitForEnding, captureStderr, encoding, timeout]
		)

	@rpc_method(check_acl="hostControl_start")
	def hostControlSafe_start(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		"""Switches on remote computers using WOL."""
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return self.hostControl_start(hostIds)

	@rpc_method(check_acl="hostControl_shutdown")
	async def hostControlSafe_shutdown(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_shutdown(hostIds)

	@rpc_method(check_acl="hostControl_reboot")
	async def hostControlSafe_reboot(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_reboot(hostIds)

	@rpc_method(check_acl="hostControl_fireEvent")
	async def hostControlSafe_fireEvent(self: BackendProtocol, event: str, hostIds: list[str] | None = None) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_fireEvent(event, hostIds)

	@rpc_method(check_acl="hostControl_showPopup")
	async def hostControlSafe_showPopup(
		self: BackendProtocol,
		message: str,
		hostIds: list[str] | None = None,
		mode: str = "prepend",
		addTimestamp: bool = True,
		displaySeconds: float = 0,
	) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_showPopup(message, hostIds, mode, addTimestamp, displaySeconds)

	@rpc_method(check_acl="hostControl_uptime")
	async def hostControlSafe_uptime(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_uptime(hostIds)

	@rpc_method(check_acl="hostControl_getActiveSessions")
	async def hostControlSafe_getActiveSessions(self: BackendProtocol, hostIds: list[str] | None = None) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_getActiveSessions(hostIds)

	@rpc_method(check_acl="hostControl_opsiclientdRpc")
	async def hostControlSafe_opsiclientdRpc(
		self: BackendProtocol, method: str, params: list[Any] | None = None, hostIds: list[str] | None = None, timeout: int | None = None
	) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_opsiclientdRpc(method, params, hostIds, timeout)

	@rpc_method(check_acl="hostControl_reachable")
	async def hostControlSafe_reachable(
		self: BackendProtocol, hostIds: list[str] | None = None, timeout: int | None = None
	) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_reachable(hostIds, timeout)

	@rpc_method(check_acl="hostControl_execute")
	async def hostControlSafe_execute(
		self: BackendProtocol,
		command: str,
		hostIds: list[str] | None = None,
		waitForEnding: bool = True,
		captureStderr: bool = True,
		encoding: str | None = None,
		timeout: int = 300,
	) -> dict[str, Any]:
		if not hostIds:
			raise BackendMissingDataError("No matching host ids found")
		return await self.hostControl_execute(command, hostIds, waitForEnding, captureStderr, encoding, timeout)
