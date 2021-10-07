# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backend
"""
import threading
import socket
import ipaddress
from urllib.parse import urlparse

from OPSI.Exceptions import BackendPermissionDeniedError
from OPSI.Backend.BackendManager import BackendManager
from OPSI.Backend.Manager.Dispatcher import _loadDispatchConfig
from OPSI.Backend.Base.Backend import describeInterface

from . import contextvar_client_address, contextvar_client_session
from .config import config, CERT_DAYS, CLIENT_CERT_DAYS
from .utils import Singleton
from .logging import logger

BackendManager.default_config =  {
	'dispatchConfigFile': config.dispatch_config_file,
	'backendConfigDir': config.backend_config_dir,
	'extensionConfigDir': config.extension_config_dir,
	'aclFile': None, # No access control by default
	'hostControlBackend': True,
	'hostControlSafeBackend': True,
	'depotBackend' : False,
	# every worker needs a database connection for full performance
	'connectionPoolSize': config.executor_workers
}

get_session_from_context = None # pylint: disable=invalid-name
def get_session():
	global get_session_from_context # pylint: disable=invalid-name, global-statement,global-variable-not-assigned
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
			client_backend_manager = BackendManager(
				user_store=get_user_store,
				option_store=get_option_store,
				aclFile=config.acl_file,
				depotBackend=True
			)
			client_backend_manager.usage_count = 0
		client_backend_manager.usage_count += 1
	return client_backend_manager

backend_manager_lock = threading.Lock()
backend_manager = None # pylint: disable=invalid-name
def get_backend():
	global backend_manager # pylint: disable=invalid-name, global-statement
	with backend_manager_lock:
		if not backend_manager:
			backend_manager = BackendManager(
				depotBackend=True
			)
	return backend_manager

backend_interface = None # pylint: disable=invalid-name
def get_backend_interface():
	global backend_interface # pylint: disable=invalid-name, global-statement
	if backend_interface is None:
		backend_interface = get_client_backend().backend_getInterface()
	return backend_interface

def get_server_role():
	for (_method, backends) in _loadDispatchConfig(config.dispatch_config_file):
		if "jsonrpc" in backends:
			return "depot"
	return "config"


class OpsiconfdBackend(metaclass=Singleton):
	def __init__(self):
		self._interface = describeInterface(self)
		self._backend = get_client_backend()
		self.method_names = [meth['name'] for meth in self._interface]

	def backend_exit(self) -> None:  # pylint: disable=no-self-use
		session = contextvar_client_session.get()
		if session:
			session.sync_delete()

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

	def getOpsiCACert(self):  # pylint: disable=invalid-name,no-self-use
		from .ssl import get_ca_cert_as_pem  # pylint: disable=import-outside-toplevel
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
				ip_addresses.add(ipaddress.ip_address(host.ipAddress).compressed)
			except ValueError as err:
				logger.error("Invalid host ip address '%s': %s", host.ipAddress, err)

		if host.getType() == "OpsiDepotserver":
			for url_type in ('depotRemoteUrl', 'depotWebdavUrl', 'repositoryRemoteUrl', 'workbenchRemoteUrl'):
				if getattr(host, url_type):
					address = urlparse(getattr(host, url_type)).hostname
					if address:
						try:
							ip_addresses.add(ipaddress.ip_address(address).compressed)
						except ValueError:
							# Not an ip address
							hostnames.add(address)
			try:
				ip_addresses.add(socket.gethostbyname(host.id))
			except socket.error as err:
				logger.warning("Failed to get ip address of host '%s': %s", host.id, err)

		from .ssl import (  # pylint: disable=import-outside-toplevel
			create_server_cert, as_pem, load_ca_key, load_ca_cert, get_domain
		)
		domain = get_domain()
		cert, key = create_server_cert(
			subject = {
				"CN": common_name,
				"OU": f"opsi@{domain}",
				"emailAddress": f"opsi@{domain}"
			},
			valid_days=CLIENT_CERT_DAYS if host.getType() == "OpsiClient" else CERT_DAYS,
			ip_addresses=ip_addresses,
			hostnames=hostnames,
			ca_key=load_ca_key(),
			ca_cert=load_ca_cert()
		)
		return as_pem(key) + as_pem(cert)
