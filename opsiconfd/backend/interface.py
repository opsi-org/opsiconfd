# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd backend interface
"""

import socket
from ipaddress import ip_address
from typing import Any, Dict, List
from urllib.parse import urlparse

from OPSI.Backend.Base.Backend import describeInterface  # type: ignore[import]
from opsicommon.exceptions import BackendPermissionDeniedError  # type: ignore[import]

from opsiconfd import contextvar_client_address, contextvar_client_session
from opsiconfd.backend import get_client_backend
from opsiconfd.check import health_check
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.utils import Singleton

backend_interface = None  # pylint: disable=invalid-name


def get_backend_interface() -> List[Dict[str, Any]]:
	global backend_interface  # pylint: disable=invalid-name, global-statement
	if backend_interface is None:
		backend_interface = get_client_backend().backend_getInterface()
		backend_methods = [method["name"] for method in backend_interface]
		for opsiconfd_method in OpsiconfdBackend().get_interface():  # pylint: disable=use-list-comprehension
			if opsiconfd_method["name"] not in backend_methods:  # pylint: disable=loop-global-usage
				backend_interface.append(opsiconfd_method)  # pylint: disable=loop-global-usage
	return backend_interface  # type: ignore


class OpsiconfdBackend(metaclass=Singleton):
	def __init__(self) -> None:
		self._interface = describeInterface(self)
		self._backend = get_client_backend()
		self.method_names = [meth["name"] for meth in self._interface]

	def _check_role(self, required_role: str) -> None:
		session = contextvar_client_session.get()
		if not session or not session.user_store:
			raise BackendPermissionDeniedError("Invalid session")

		if required_role == "admin":
			if session.user_store.isAdmin:
				return
			raise BackendPermissionDeniedError("Insufficient permissions")

		raise ValueError(f"Invalid role {required_role!r}")

	def get_interface(self) -> List[Dict[str, Any]]:
		return self._interface

	def backend_exit(self) -> None:
		session = contextvar_client_session.get()
		if session:
			session.sync_delete()

	def server_checkHealth(self) -> dict:  # pylint: disable=invalid-name
		self._check_role("admin")
		return health_check()

	def getDomain(self) -> str:  # pylint: disable=invalid-name
		try:
			client_address = contextvar_client_address.get()
			if not client_address:
				raise ValueError("Failed to get client address")
			if client_address not in ("127.0.0.1", "::1"):
				names = socket.gethostbyaddr(client_address)
				if names[0] and names[0].count(".") >= 2:
					return ".".join(names[0].split(".")[1:])
		except Exception as err:  # pylint: disable=broad-except
			logger.debug("Failed to get domain by client address: %s", err)
		return self._backend.getDomain()  # pylint: disable=no-member

	def getOpsiCACert(self) -> str:  # pylint: disable=invalid-name
		from opsiconfd.ssl import (  # pylint: disable=import-outside-toplevel
			get_ca_cert_as_pem,
		)

		return get_ca_cert_as_pem()

	def host_getTLSCertificate(self, hostId: str) -> str:  # pylint: disable=invalid-name,too-many-locals
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Invalid session")
		host = self._backend.host_getObjects(id=hostId)  # pylint: disable=no-member
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

		from opsiconfd.ssl import (  # pylint: disable=import-outside-toplevel
			as_pem,
			create_server_cert,
			get_domain,
			load_ca_cert,
			load_ca_key,
		)

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
