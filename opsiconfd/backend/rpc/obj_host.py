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
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, List, Protocol
from urllib.parse import urlparse

from opsicommon.exceptions import BackendPermissionDeniedError  # type: ignore[import]
from opsicommon.objects import (  # type: ignore[import]
	Host,
	OpsiClient,
	OpsiConfigserver,
	OpsiDepotserver,
)
from opsicommon.types import forceList  # type: ignore[import]

from opsiconfd import contextvar_client_session
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.ssl import (  # pylint: disable=import-outside-toplevel
	as_pem,
	create_server_cert,
	get_domain,
	load_ca_cert,
	load_ca_key,
)

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCHostMixin(Protocol):
	@rpc_method
	def host_insertObject(self: BackendProtocol, host: dict | Host) -> None:  # pylint: disable=invalid-name
		"""
		Creates a new Host object in the backend.
		If the Host object already exists, it will be completely overwritten with the new values.
		Attributes that are not passed (or passed with the value 'null') will be set to 'null' in the backend.
		"""
		self._mysql.insert_object(table="HOST", obj=host, ace=self._get_ace("host_insertObject"), create=True, set_null=True)

	@rpc_method
	def host_updateObject(self: BackendProtocol, host: dict | Host) -> None:  # pylint: disable=invalid-name
		"""
		Updates an Host object in the backend.
		Attributes that are not passed (or passed with the value 'null'), will not be changed in the backend.
		If the object does not exist, no change takes place, no object is created.
		"""
		self._mysql.insert_object(table="HOST", obj=host, ace=self._get_ace("host_updateObject"), create=False, set_null=False)

	@rpc_method
	def host_createObjects(self: BackendProtocol, hosts: List[dict] | List[Host] | dict | Host) -> None:  # pylint: disable=invalid-name
		"""
		An object or a list of objects can be passed. Each object is passed internally to 'insertObject'.
		"""
		for host in forceList(hosts):
			self._mysql.insert_object(table="HOST", obj=host, ace=self._get_ace("host_createObjects"), create=True, set_null=True)

	@rpc_method
	def host_updateObjects(self: BackendProtocol, hosts: List[dict] | List[Host] | dict | Host) -> None:  # pylint: disable=invalid-name
		"""
		An object or a list of objects can be passed.
		Each object will be updated if it exists or created if it does not exist yet.
		"""
		for host in forceList(hosts):
			self._mysql.insert_object(table="HOST", obj=host, ace=self._get_ace("host_updateObjects"), create=True, set_null=False)

	@rpc_method
	def host_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		return self._mysql.get_idents(table="HOST", object_type=Host, ace=self._get_ace("host_getObjects"), ident_type=returnType, filter=filter)

	@rpc_method
	def host_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		return self._mysql.get_objects(
			table="HOST", object_type=Host, ace=self._get_ace("host_getObjects"), return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def host_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[Host]:  # pylint: disable=redefined-builtin,invalid-name
		return self._mysql.get_objects(
			table="HOST", object_type=Host, ace=self._get_ace("host_getObjects"), return_type="object", attributes=attributes, filter=filter
		)

	@rpc_method
	def host_deleteObjects(self: BackendProtocol, hosts: List[dict] | List[Host] | dict | Host) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("host_deleteObjects")
		host_ids = [host.id if isinstance(host, Host) else host["id"] for host in forceList(hosts)]
		allowed_client_ids = self._mysql.get_allowed_client_ids(ace)
		if allowed_client_ids is not None:
			for host_id in host_ids:
				if host_id not in allowed_client_ids:
					raise BackendPermissionDeniedError(f"No permission to delete host {host_id}")

		with self._mysql.session() as session:
			logger.info("Deleting hosts: %s", host_ids)
			session.execute("DELETE FROM `HOST` WHERE hostId IN :host_ids", params={"host_ids": host_ids})
			for table in self._mysql.tables:
				if table.startswith("HARDWARE_CONFIG_"):
					session.execute(f"DELETE FROM `{table}` WHERE hostId IN :host_ids", params={"host_ids": host_ids})

	@rpc_method
	def host_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.host_deleteObjects([{"id": id}])

	@rpc_method
	def host_createOpsiClient(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		opsiHostKey: str = None,  # pylint: disable=unused-argument
		description: str = None,  # pylint: disable=unused-argument
		notes: str = None,  # pylint: disable=unused-argument
		hardwareAddress: str = None,  # pylint: disable=unused-argument
		ipAddress: str = None,  # pylint: disable=unused-argument
		inventoryNumber: str = None,  # pylint: disable=unused-argument
		oneTimePassword: str = None,  # pylint: disable=unused-argument
		created: str = None,  # pylint: disable=unused-argument
		lastSeen: str = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.host_createObjects([OpsiClient.fromHash(_hash)])

	@rpc_method
	def host_createOpsiDepotserver(  # pylint: disable=too-many-arguments,invalid-name,too-many-locals
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		opsiHostKey: str = None,  # pylint: disable=unused-argument
		depotLocalUrl: str = None,  # pylint: disable=unused-argument
		depotRemoteUrl: str = None,  # pylint: disable=unused-argument
		depotWebdavUrl: str = None,  # pylint: disable=unused-argument
		repositoryLocalUrl: str = None,  # pylint: disable=unused-argument
		repositoryRemoteUrl: str = None,  # pylint: disable=unused-argument
		description: str = None,  # pylint: disable=unused-argument
		notes: str = None,  # pylint: disable=unused-argument
		hardwareAddress: str = None,  # pylint: disable=unused-argument
		ipAddress: str = None,  # pylint: disable=unused-argument
		inventoryNumber: str = None,  # pylint: disable=unused-argument
		networkAddress: str = None,  # pylint: disable=unused-argument
		maxBandwidth: str = None,  # pylint: disable=unused-argument
		isMasterDepot: bool = None,  # pylint: disable=unused-argument
		masterDepotId: str = None,  # pylint: disable=unused-argument
		workbenchLocalUrl: str = None,  # pylint: disable=unused-argument
		workbenchRemoteUrl: str = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.host_createObjects([OpsiDepotserver.fromHash(_hash)])

	@rpc_method
	def host_createOpsiConfigserver(  # pylint: disable=too-many-arguments,invalid-name,too-many-locals
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin,unused-argument
		opsiHostKey: str = None,  # pylint: disable=unused-argument
		depotLocalUrl: str = None,  # pylint: disable=unused-argument
		depotRemoteUrl: str = None,  # pylint: disable=unused-argument
		depotWebdavUrl: str = None,  # pylint: disable=unused-argument
		repositoryLocalUrl: str = None,  # pylint: disable=unused-argument
		repositoryRemoteUrl: str = None,  # pylint: disable=unused-argument
		description: str = None,  # pylint: disable=unused-argument
		notes: str = None,  # pylint: disable=unused-argument
		hardwareAddress: str = None,  # pylint: disable=unused-argument
		ipAddress: str = None,  # pylint: disable=unused-argument
		inventoryNumber: str = None,  # pylint: disable=unused-argument
		networkAddress: str = None,  # pylint: disable=unused-argument
		maxBandwidth: str = None,  # pylint: disable=unused-argument
		isMasterDepot: bool = None,  # pylint: disable=unused-argument
		masterDepotId: str = None,  # pylint: disable=unused-argument
		workbenchLocalUrl: str = None,  # pylint: disable=unused-argument
		workbenchRemoteUrl: str = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.host_createObjects([OpsiConfigserver.fromHash(_hash)])

	@rpc_method
	def host_getTLSCertificate(self: BackendProtocol, hostId: str) -> str:  # pylint: disable=invalid-name,too-many-locals
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Invalid session")
		host = self.host_getObjects(id=hostId)  # pylint: disable=no-member
		if not host or not host[0] or host[0].getType() not in ("OpsiDepotserver", "OpsiClient"):
			raise BackendPermissionDeniedError(f"Invalid host: {hostId}")
		host = host[0]
		if not session.user_store.isAdmin and session.user_store.username != host.id:
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
						try:  # pylint: disable=loop-try-except-usage
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
