# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""


import threading
import socket
import ipaddress
from urllib.parse import urlparse

from OPSI.Exceptions import BackendPermissionDeniedError
from OPSI.Backend import no_export
from OPSI.Backend.BackendManager import BackendManager
from OPSI.Backend.Manager.Dispatcher import _loadDispatchConfig
from OPSI.Backend.Base.Backend import describeInterface

from . import contextvar_client_address, contextvar_client_session
from .config import config
from .utils import Singleton
from .logging import logger

backend_config =  {
	'dispatchConfigFile': config.dispatch_config_file,
	'backendConfigDir': config.backend_config_dir,
	'extensionConfigDir': config.extension_config_dir,
	'aclFile': config.acl_file,
	'hostControlBackend': True,
	'hostControlSafeBackend': True,
	'depotBackend' : True,
	# every worker needs a database connection for full performance
	'connectionpoolsize': config.executor_workers
}

get_session_from_context = None # pylint: disable=invalid-name
def get_session():
	global get_session_from_context # pylint: disable=invalid-name, global-statement
	if not get_session_from_context:
		from .session import get_session_from_context # pylint: disable=import-outside-toplevel, redefined-outer-name
	return get_session_from_context()

def get_user_store():
	return get_session().user_store

def get_option_store():
	return get_session().option_store

client_backend_manager_lock = threading.Lock()
client_backend_manager = None # pylint: disable=invalid-name
def get_client_backend():
	global client_backend_manager # pylint: disable=invalid-name, global-statement
	with client_backend_manager_lock:
		if not client_backend_manager:
			backend_config["user_store"] = get_user_store
			backend_config["option_store"] = get_option_store
			client_backend_manager = BackendManager(**backend_config)
			client_backend_manager.usage_count = 0
		client_backend_manager.usage_count += 1
	return client_backend_manager

backend_manager_lock = threading.Lock()
backend_manager = None # pylint: disable=invalid-name
def get_backend():
	global backend_manager # pylint: disable=invalid-name, global-statement
	with backend_manager_lock:
		if not backend_manager:
			bc = dict(backend_config) # pylint: disable=invalid-name
			if "aclFile" in bc:
				del bc["aclFile"]
			backend_manager = BackendManager(**bc)
	return backend_manager

backend_interface = None # pylint: disable=invalid-name
def get_backend_interface():
	global backend_interface # pylint: disable=invalid-name, global-statement
	if backend_interface is None:
		opsiconfd_backend = OpsiconfdBackend()
		backend_interface = []
		for method in get_client_backend().backend_getInterface():
			if not method["name"] in opsiconfd_backend.method_names:
				backend_interface.append(method)
		backend_interface.extend(opsiconfd_backend.get_interface())
		backend_interface = sorted(backend_interface, key=lambda meth: meth['name'])
	return backend_interface

def get_server_role():
	for (_method, backends) in _loadDispatchConfig(config.dispatch_config_file):
		if "jsonrpc" in backends:
			return "depot"
	return "config"


class OpsiconfdBackend(metaclass=Singleton):
	def __init__(self):
		self._interface = describeInterface(self)
		self.method_names = [meth['name'] for meth in self._interface]
		self._backend = get_client_backend()

	@no_export
	def get_interface(self):
		return self._interface

	def backend_exit(self) -> None:  # pylint: disable=no-self-use
		return

	def getDomain(self) -> str:  # pylint: disable=invalid-name
		try:
			client_address = contextvar_client_address.get()
			if not client_address:
				raise ValueError("Failed to get client address")
			names = socket.gethostbyaddr(client_address)
			if names[0] and "." in names[0]:
				return ".".join(names[0].split(".")[1:])
		except Exception as err:  # pylint: disable=broad-except
			logger.debug("Failed to get domain by client address: %s", err)
		return self._backend.getDomain()  # pylint: disable=no-member

	def getOpsiCACert(self):  # pylint: disable=invalid-name,no-self-use
		logger.devel(contextvar_client_address.get())
		from .ssl import get_ca_cert_as_pem  # pylint: disable=import-outside-toplevel
		return get_ca_cert_as_pem()

	def host_getTLSCertificate(self, hostId: str) -> str:  # pylint: disable=invalid-name
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Invalid session")
		host = self._backend.host_getObjects(type="OpsiDepotserver", id=hostId)  # pylint: disable=no-member
		if not host or not host[0] or host[0].getType() != "OpsiDepotserver":
			raise BackendPermissionDeniedError(f"Not a depotserver: {hostId}")
		host = host[0]
		if not session.user_store.isAdmin and session.user_store.username != host.id:
			raise BackendPermissionDeniedError("Insufficient permissions")

		common_name = host.id
		ip_addresses = set()
		hostnames = set()
		if host.ipAddress:
			try:
				ip_addresses.add(ipaddress.ip_address(host.ipAddress).compressed)
			except ValueError as err:
				logger.error("Invalid depot ip address '%s': %s", host.ipAddress, err)
		try:
			ip_addresses.add(socket.gethostbyname(host.id))
		except socket.error as err:
			logger.warning("Failed to get ip address of '%s': %s", host.id, err)

		for url_type in ('depotRemoteUrl', 'depotWebdavUrl', 'repositoryRemoteUrl', 'workbenchRemoteUrl'):
			if getattr(host, url_type):
				address = urlparse(getattr(host, url_type)).hostname
				if address:
					try:
						ip_addresses.add(ipaddress.ip_address(address).compressed)
					except ValueError:
						# Not an ip address
						hostnames.add(address)

		from .ssl import create_server_cert, as_pem  # pylint: disable=import-outside-toplevel
		cert, key = create_server_cert(common_name, ip_addresses, hostnames)
		return as_pem(key) + as_pem(cert)
