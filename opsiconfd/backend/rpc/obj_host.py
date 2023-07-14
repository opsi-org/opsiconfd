# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.host
"""

from __future__ import annotations

import socket
from copy import deepcopy
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import urlparse

from opsicommon.exceptions import (
	BackendError,
	BackendMissingDataError,
	BackendPermissionDeniedError,
)
from opsicommon.objects import Host, OpsiClient, OpsiConfigserver, OpsiDepotserver
from opsicommon.types import forceHostId, forceObjectClass, forceObjectClassList

from opsiconfd import contextvar_client_session
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.messagebus.redis import get_websocket_connected_users
from opsiconfd.ssl import (  # pylint: disable=import-outside-toplevel
	as_pem,
	create_server_cert,
	get_domain,
	load_ca_cert,
	load_ca_key,
)
from opsiconfd.metrics.statistics import setup_metric_downsampling
from opsiconfd.redis import redis_client

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCHostMixin(Protocol):
	def _host_check_duplicate_hardware_address(self: BackendProtocol, host: Host) -> None:
		if not self._mysql.unique_hardware_addresses or not host.hardwareAddress or host.hardwareAddress.startswith("00:00:00"):
			return

		with self._mysql.session() as session:  # pylint: disable=redefined-argument-from-local
			res = session.execute(
				"""
				SELECT hostId FROM `HOST`
				WHERE hostId != :hostId AND hardwareAddress = :hardwareAddress
				LIMIT 1
				""",
				params={"hostId": host.id, "hardwareAddress": host.hardwareAddress},
			).fetchone()
			if res:
				raise ValueError(f"Hardware address {host.hardwareAddress!r} is already used by host {res[0]!r}")

	def host_bulkInsertObjects(self: BackendProtocol, hosts: list[dict] | list[Host]) -> None:  # pylint: disable=invalid-name
		self._mysql.bulk_insert_objects(table="HOST", objs=hosts)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def host_insertObject(self: BackendProtocol, host: dict | Host) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("host_insertObject")
		host = forceObjectClass(host, Host)
		self._host_check_duplicate_hardware_address(host)
		self._mysql.insert_object(table="HOST", obj=host, ace=ace, create=True, set_null=True)
		if not self.events_enabled:
			return

		self._send_messagebus_event("host_created", data={"type": host.getType(), "id": host.id})
		if host.getType() == "OpsiClient":
			self.opsipxeconfd_hosts_updated([host.id])
			self.dhcpd_control_hosts_updated([host.id])

	@rpc_method(check_acl=False)
	def host_updateObject(self: BackendProtocol, host: dict | Host) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("host_updateObject")
		host = forceObjectClass(host, Host)
		self._host_check_duplicate_hardware_address(host)
		self._mysql.insert_object(table="HOST", obj=host, ace=ace, create=False, set_null=False)
		if not self.events_enabled:
			return

		self._send_messagebus_event("host_updated", data={"type": host.getType(), "id": host.id})
		if host.getType() == "OpsiClient":
			self.opsipxeconfd_hosts_updated([host.id])
			self.dhcpd_control_hosts_updated([host.id])

	@rpc_method(check_acl=False)
	def host_createObjects(self: BackendProtocol, hosts: list[dict] | list[Host] | dict | Host) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("host_createObjects")
		hosts = forceObjectClassList(hosts, Host)
		with self._mysql.session() as session:
			for host in hosts:
				self._host_check_duplicate_hardware_address(host)
				self._mysql.insert_object(table="HOST", obj=host, ace=ace, create=True, set_null=True, session=session)
		if not self.events_enabled:
			return

		client_ids = []
		for host in hosts:
			self._send_messagebus_event("host_created", data={"type": host.getType(), "id": host.id})
			if host.getType() == "OpsiClient":
				client_ids.append(host.id)
		if client_ids:
			self.opsipxeconfd_hosts_updated(client_ids)
			self.dhcpd_control_hosts_updated(client_ids)

	@rpc_method(check_acl=False)
	def host_updateObjects(self: BackendProtocol, hosts: list[dict] | list[Host] | dict | Host) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("host_updateObjects")
		hosts = forceObjectClassList(hosts, Host)
		with self._mysql.session() as session:
			for host in hosts:
				self._host_check_duplicate_hardware_address(host)
				self._mysql.insert_object(table="HOST", obj=host, ace=ace, create=True, set_null=False, session=session)
		if not self.events_enabled:
			return

		client_ids = []
		for host in hosts:
			self._send_messagebus_event("host_updated", data={"type": host.getType(), "id": host.id})
			if host.getType() == "OpsiClient":
				client_ids.append(host.id)
		if client_ids:
			self.opsipxeconfd_hosts_updated(client_ids)
			self.dhcpd_control_hosts_updated(client_ids)

	@rpc_method(check_acl=False)
	def host_getObjects(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[Host]:
		ace = self._get_ace("host_getObjects")
		return self._mysql.get_objects(table="HOST", object_type=Host, ace=ace, return_type="object", attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def host_getHashes(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[dict]:
		ace = self._get_ace("host_getObjects")
		return self._mysql.get_objects(table="HOST", object_type=Host, ace=ace, return_type="dict", attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def host_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("host_getObjects")
		return self._mysql.get_idents(table="HOST", object_type=Host, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def host_deleteObjects(self: BackendProtocol, hosts: list[dict] | list[Host] | dict | Host) -> None:  # pylint: disable=invalid-name
		if not hosts:
			return
		ace = self._get_ace("host_deleteObjects")
		query, params, idents = self._mysql.delete_query(table="HOST", object_type=Host, obj=hosts, ace=ace)
		host_ids = [ident["id"] for ident in idents]
		with self._mysql.session() as session:
			session.execute(query, params=params)
			for table in self._mysql.tables:
				if table.startswith("HARDWARE_CONFIG_"):
					session.execute(f"DELETE FROM `{table}` WHERE hostId IN :host_ids", params={"host_ids": host_ids})
		if not self.events_enabled:
			return

		for host_id in host_ids:
			self._send_messagebus_event("host_deleted", data={"id": host_id})
		self.opsipxeconfd_hosts_deleted(host_ids)
		self.dhcpd_control_hosts_deleted(host_ids)

	@rpc_method(check_acl=False)
	def host_delete(self: BackendProtocol, id: list[str] | str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		idents = self.host_getIdents(returnType="dict", id=id)
		if idents:
			self.host_deleteObjects(idents)

	@rpc_method(check_acl=False)
	def host_createOpsiClient(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		opsiHostKey: str | None = None,  # pylint: disable=unused-argument
		description: str | None = None,  # pylint: disable=unused-argument
		notes: str | None = None,  # pylint: disable=unused-argument
		hardwareAddress: str | None = None,  # pylint: disable=unused-argument
		ipAddress: str | None = None,  # pylint: disable=unused-argument
		inventoryNumber: str | None = None,  # pylint: disable=unused-argument
		oneTimePassword: str | None = None,  # pylint: disable=unused-argument
		created: str | None = None,  # pylint: disable=unused-argument
		lastSeen: str | None = None,  # pylint: disable=unused-argument
		systemUUID: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.host_createObjects([OpsiClient.fromHash(_hash)])

	@rpc_method(check_acl=False)
	def host_createOpsiDepotserver(  # pylint: disable=too-many-arguments,invalid-name,too-many-locals
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		opsiHostKey: str | None = None,  # pylint: disable=unused-argument
		depotLocalUrl: str | None = None,  # pylint: disable=unused-argument
		depotRemoteUrl: str | None = None,  # pylint: disable=unused-argument
		depotWebdavUrl: str | None = None,  # pylint: disable=unused-argument
		repositoryLocalUrl: str | None = None,  # pylint: disable=unused-argument
		repositoryRemoteUrl: str | None = None,  # pylint: disable=unused-argument
		description: str | None = None,  # pylint: disable=unused-argument
		notes: str | None = None,  # pylint: disable=unused-argument
		hardwareAddress: str | None = None,  # pylint: disable=unused-argument
		ipAddress: str | None = None,  # pylint: disable=unused-argument
		inventoryNumber: str | None = None,  # pylint: disable=unused-argument
		networkAddress: str | None = None,  # pylint: disable=unused-argument
		maxBandwidth: str | None = None,  # pylint: disable=unused-argument
		isMasterDepot: bool | None = None,  # pylint: disable=unused-argument
		masterDepotId: str | None = None,  # pylint: disable=unused-argument
		workbenchLocalUrl: str | None = None,  # pylint: disable=unused-argument
		workbenchRemoteUrl: str | None = None,  # pylint: disable=unused-argument
		systemUUID: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.host_createObjects([OpsiDepotserver.fromHash(_hash)])

	@rpc_method(check_acl=False)
	def host_createOpsiConfigserver(  # pylint: disable=too-many-arguments,invalid-name,too-many-locals
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		opsiHostKey: str | None = None,  # pylint: disable=unused-argument
		depotLocalUrl: str | None = None,  # pylint: disable=unused-argument
		depotRemoteUrl: str | None = None,  # pylint: disable=unused-argument
		depotWebdavUrl: str | None = None,  # pylint: disable=unused-argument
		repositoryLocalUrl: str | None = None,  # pylint: disable=unused-argument
		repositoryRemoteUrl: str | None = None,  # pylint: disable=unused-argument
		description: str | None = None,  # pylint: disable=unused-argument
		notes: str | None = None,  # pylint: disable=unused-argument
		hardwareAddress: str | None = None,  # pylint: disable=unused-argument
		ipAddress: str | None = None,  # pylint: disable=unused-argument
		inventoryNumber: str | None = None,  # pylint: disable=unused-argument
		networkAddress: str | None = None,  # pylint: disable=unused-argument
		maxBandwidth: str | None = None,  # pylint: disable=unused-argument
		isMasterDepot: bool | None = None,  # pylint: disable=unused-argument
		masterDepotId: str | None = None,  # pylint: disable=unused-argument
		workbenchLocalUrl: str | None = None,  # pylint: disable=unused-argument
		workbenchRemoteUrl: str | None = None,  # pylint: disable=unused-argument
		systemUUID: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.host_createObjects([OpsiConfigserver.fromHash(_hash)])

	@rpc_method(check_acl=False)
	def host_getTLSCertificate(self: BackendProtocol, hostId: str) -> str:  # pylint: disable=invalid-name,too-many-locals
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Invalid session")
		host = self.host_getObjects(id=hostId)  # pylint: disable=no-member
		if not host or not host[0] or host[0].getType() not in ("OpsiDepotserver", "OpsiClient"):
			raise BackendPermissionDeniedError(f"Invalid host: {hostId}")
		host = host[0]
		if not session.is_admin and session.username != host.id:
			raise BackendPermissionDeniedError("Insufficient permissions")

		common_name = host.id
		ip_addresses = {"127.0.0.1", "::1"}
		hostnames = {"localhost", common_name}
		if host.ipAddress:
			try:
				ip_addresses.add(ip_address(host.ipAddress).compressed)
			except ValueError as err:
				logger.error("Invalid host ip address '%s': %s", host.ipAddress, err)

		if host.getType() == "OpsiDepotserver":
			for url_type in ("depotRemoteUrl", "depotWebdavUrl", "repositoryRemoteUrl", "workbenchRemoteUrl"):
				if getattr(host, url_type):
					address = urlparse(getattr(host, url_type)).hostname
					if address:
						try:
							ip_addresses.add(ip_address(address).compressed)
						except ValueError:
							# Not an ip address
							hostnames.add(address)
			try:
				ip_addresses.add(socket.gethostbyname(host.id))
			except socket.error as err:
				logger.warning("Failed to get ip address of host '%s': %s", host.id, err)

		domain = get_domain()
		cert, key = create_server_cert(
			subject={"CN": common_name, "OU": f"opsi@{domain}", "emailAddress": f"opsi@{domain}"},
			valid_days=(config.ssl_client_cert_valid_days if host.getType() == "OpsiClient" else config.ssl_server_cert_valid_days),
			ip_addresses=ip_addresses,
			hostnames=hostnames,
			ca_key=load_ca_key(),
			ca_cert=load_ca_cert(),
		)
		return as_pem(key) + as_pem(cert)

	@rpc_method(check_acl=False)
	def host_renameOpsiClient(  # pylint: disable=redefined-builtin,invalid-name,too-many-locals,too-many-branches,too-many-statements
		self: BackendProtocol, id: str, newId: str
	) -> None:
		cur_client_id = forceHostId(id)  # pylint: disable=invalid-name
		new_client_id = forceHostId(newId)

		logger.info("Renaming client %s to %s...", cur_client_id, new_client_id)

		clients = self.host_getObjects(type="OpsiClient", id=cur_client_id)
		try:
			client = clients[0]
		except IndexError as err:
			raise BackendMissingDataError(f"Cannot rename: client '{cur_client_id}' not found") from err

		if self.host_getObjects(id=new_client_id):
			raise BackendError(f"Cannot rename: host '{new_client_id}' already exists")

		logger.info("Processing group mappings...")
		object_to_groups = []
		for object_to_group in self.objectToGroup_getObjects(groupType="HostGroup", objectId=client.id):
			object_to_group.setObjectId(new_client_id)
			object_to_groups.append(object_to_group)

		logger.info("Processing products on client...")
		product_on_clients = []
		for product_on_client in self.productOnClient_getObjects(clientId=client.id):
			product_on_client.setClientId(new_client_id)
			product_on_clients.append(product_on_client)

		logger.info("Processing product property states...")
		product_property_states = []
		for product_property_state in self.productPropertyState_getObjects(objectId=client.id):
			product_property_state.setObjectId(new_client_id)
			product_property_states.append(product_property_state)

		logger.info("Processing config states...")
		config_states = []
		for config_state in self.configState_getObjects(objectId=client.id):
			config_state.setObjectId(new_client_id)
			config_states.append(config_state)

		logger.info("Processing software audit data...")
		audit_software_on_clients = []
		for audit_software_on_client in self.auditSoftwareOnClient_getObjects(clientId=client.id):
			audit_software_on_client.setClientId(new_client_id)
			audit_software_on_clients.append(audit_software_on_client)

		logger.info("Processing hardware audit data...")
		audit_hardware_on_hosts = []
		for audit_hardware_on_host in self.auditHardwareOnHost_getObjects(hostId=client.id):
			audit_hardware_on_host.setHostId(new_client_id)
			audit_hardware_on_hosts.append(audit_hardware_on_host)

		logger.info("Processing license data...")
		license_on_clients = []
		for license_on_client in self.licenseOnClient_getObjects(clientId=client.id):
			license_on_client.setClientId(new_client_id)
			license_on_clients.append(license_on_client)

		logger.info("Processing software licenses...")
		software_licenses = []
		for software_license in self.softwareLicense_getObjects(boundToHost=client.id):
			software_license.setBoundToHost(new_client_id)
			software_licenses.append(software_license)

		logger.debug("Deleting client %s", client)
		self.host_deleteObjects([client])

		logger.info("Updating client %s...", client.id)
		client.setId(new_client_id)
		self.host_createObjects([client])

		if object_to_groups:
			logger.info("Updating group mappings...")
			self.objectToGroup_createObjects(object_to_groups)
		if product_on_clients:
			logger.info("Updating products on client...")
			self.productOnClient_createObjects(product_on_clients)
		if product_property_states:
			logger.info("Updating product property states...")
			self.productPropertyState_createObjects(product_property_states)
		if config_states:
			logger.info("Updating config states...")
			self.configState_createObjects(config_states)
		if audit_software_on_clients:
			logger.info("Updating software audit data...")
			self.auditSoftwareOnClient_createObjects(audit_software_on_clients)
		if audit_hardware_on_hosts:
			logger.info("Updating hardware audit data...")
			self.auditHardwareOnHost_createObjects(audit_hardware_on_hosts)
		if license_on_clients:
			logger.info("Updating license data...")
			self.licenseOnClient_createObjects(license_on_clients)
		if software_licenses:
			logger.info("Updating software licenses...")
			self.softwareLicense_createObjects(software_licenses)

	@rpc_method(check_acl=False)
	def host_renameOpsiDepotserver(  # pylint: disable=invalid-name,too-many-branches,too-many-statements,too-many-locals
		self: BackendProtocol, oldId: str, newId: str
	) -> None:
		"""
		Rename OpsiDepotserver with id `oldId` to `newId`.

		References to the old id will be changed aswell.

		:raises BackendMissingDataError: If no depot `oldId` is found.
		:raises BackendError: If depot `newId` already exists.
		:param oldId: ID of the server to change.
		:type oldId: str
		:param oldId: New ID.
		:type newId: str
		"""
		cur_server_id = forceHostId(oldId)
		new_server_id = forceHostId(newId)
		cur_hostname = cur_server_id.split(".")[0]
		new_hostname = new_server_id.split(".")[0]

		depots = self.host_getObjects(type="OpsiDepotserver", id=cur_server_id)
		try:
			depot = depots[0]
		except IndexError as err:
			raise BackendMissingDataError(f"Cannot rename: depot '{cur_server_id}' not found") from err

		if self.host_getObjects(id=new_server_id):
			logger.warning("Deleting host %r", new_server_id)
			self.host_delete(id=[new_server_id])

		logger.info("Renaming depot %s to %s", cur_server_id, new_server_id)

		logger.info("Processing ProductOnDepots...")
		product_on_depots = []
		for product_on_depot in self.productOnDepot_getObjects(depotId=cur_server_id):
			product_on_depot.setDepotId(new_server_id)
			product_on_depots.append(product_on_depot)

		def replace_server_id(some_list: list[str]) -> bool:
			"""
			Replaces occurrences of `oldId` with `newId` in `some_list`.

			If some_list is the wrong type or no change was made `False`
			will be returned.

			:type some_list: list
			:returns: `True` if a change was made.
			:rtype: bool
			"""
			try:
				some_list.remove(cur_server_id)
				some_list.append(new_server_id)
				return True
			except (ValueError, AttributeError):
				return False

		logger.info("Processing ProductProperties...")
		modified_product_properties = []
		for product_property in self.productProperty_getObjects():
			changed = replace_server_id(product_property.possibleValues)
			changed = replace_server_id(product_property.defaultValues) or changed

			if changed:
				modified_product_properties.append(product_property)

		if modified_product_properties:
			logger.info("Updating ProductProperties...")
			self.productProperty_updateObjects(modified_product_properties)

		logger.info("Processing ProductPropertyStates...")
		product_property_states = []
		for product_property_state in self.productPropertyState_getObjects(objectId=cur_server_id):
			product_property_state.setObjectId(new_server_id)
			replace_server_id(product_property_state.values)
			product_property_states.append(product_property_state)

		logger.info("Processing Configs...")
		modified_configs = []
		for conf in self.config_getObjects():
			changed = replace_server_id(conf.possibleValues)
			changed = replace_server_id(conf.defaultValues) or changed
			if changed:
				modified_configs.append(conf)

		if modified_configs:
			logger.info("Updating Configs...")
			self.config_updateObjects(modified_configs)

		logger.info("Processing ConfigStates...")
		config_states = []
		for config_state in self.configState_getObjects(objectId=cur_server_id):
			config_state.setObjectId(new_server_id)
			replace_server_id(config_state.values)
			config_states.append(config_state)
		for config_state in self.configState_getObjects(configId=["clientconfig.depot.id"]):
			if replace_server_id(config_state.values):
				config_states.append(config_state)

		def change_address(value: str) -> str:
			new_value = value.replace(cur_server_id, new_server_id)
			new_value = new_value.replace(cur_hostname, new_hostname)
			logger.debug("Changed %s to %s", value, new_value)
			return new_value

		old_depot = deepcopy(depot)
		if old_depot.hardwareAddress:
			# Hardware address needs to be unique
			old_depot.hardwareAddress = None
			self.host_createObjects([old_depot])

		logger.info("Updating depot and it's urls...")
		depot.setId(new_server_id)
		if depot.repositoryRemoteUrl:
			depot.setRepositoryRemoteUrl(change_address(depot.repositoryRemoteUrl))
		if depot.depotRemoteUrl:
			depot.setDepotRemoteUrl(change_address(depot.depotRemoteUrl))
		if depot.depotWebdavUrl:
			depot.setDepotWebdavUrl(change_address(depot.depotWebdavUrl))
		if depot.workbenchRemoteUrl:
			depot.setWorkbenchRemoteUrl(change_address(depot.workbenchRemoteUrl))
		self.host_createObjects([depot])

		if product_on_depots:
			logger.info("Updating ProductOnDepots...")
			self.productOnDepot_createObjects(product_on_depots)
		if product_property_states:
			logger.info("Updating ProductPropertyStates...")
			self.productPropertyState_createObjects(product_property_states)
		if config_states:
			logger.info("Updating ConfigStates...")
			self.configState_createObjects(config_states)

		logger.info("Deleting old depot %s", old_depot)
		self.host_deleteObjects([old_depot])

		with redis_client() as redis:
			for key_b in redis.scan_iter(f"{config.redis_key()}:*"):
				key_b = cast(bytes, key_b)
				key = key_b.decode("utf-8")
				if f":{cur_hostname}:" in key or key.endswith(f":{cur_hostname}"):
					redis.rename(key, key.replace(f":{cur_hostname}", f":{new_hostname}"))  # type: ignore[no-untyped-call]

	@rpc_method(check_acl=False)
	async def host_getMessagebusConnectedIds(  # pylint: disable=invalid-name
		self: BackendProtocol, hostIds: list[str] | None = None
	) -> list[str]:
		"""
		Return a list of host IDs connected to the messagebus.
		The hostId parameter can be used to limit the list to the IDs passed.
		"""
		return [h async for h in get_websocket_connected_users(user_ids=hostIds, user_type="depot")] + [
			h async for h in get_websocket_connected_users(user_ids=hostIds, user_type="client")
		]
