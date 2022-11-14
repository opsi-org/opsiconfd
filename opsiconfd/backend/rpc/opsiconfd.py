# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd backend interface
"""

import socket
from inspect import getfullargspec, getmembers, ismethod, signature
from ipaddress import ip_address
from textwrap import dedent
from typing import Any, Dict, List
from urllib.parse import urlparse

from opsicommon.exceptions import BackendPermissionDeniedError  # type: ignore[import]

from opsiconfd import contextvar_client_address, contextvar_client_session
from opsiconfd.backup import create_backup
from opsiconfd.check import health_check
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.utils import Singleton

from .. import get_client_backend
from ..auth import RPCACE, read_acl_file
from ..mysql import MySQLConnection
from .ext_wim import RPCExtWIMMixin
from .extender import RPCExtenderMixin
from .obj_config import RPCConfigMixin
from .obj_config_state import RPCConfigStateMixin
from .obj_host import RPCHostMixin

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


def describe_interface(instance: Any) -> List[Dict[str, Any]]:  # pylint: disable=too-many-locals
	"""
	Describes what public methods are available and the signatures they use.

	These methods are represented as a dict with the following keys: \
	*name*, *params*, *args*, *varargs*, *keywords*, *defaults*.

	:rtype: [{},]
	"""
	methods = {}
	for _, function in getmembers(instance, ismethod):
		method_name = function.__name__
		if not getattr(function, "rpc_method", False):
			continue

		spec = getfullargspec(function)
		sig = signature(function)
		args = spec.args
		defaults = spec.defaults
		params = [arg for arg in args if arg != "self"]  # pylint: disable=loop-invariant-statement
		annotations = {}
		for param in params:
			str_param = str(sig.parameters[param])
			if ": " in str_param:
				annotations[param] = str_param.split(": ", 1)[1].split(" = ", 1)[0]

		if defaults is not None:
			offset = len(params) - len(defaults)
			for i in range(len(defaults)):
				index = offset + i
				params[index] = f"*{params[index]}"

		for index, element in enumerate((spec.varargs, spec.varkw), start=1):
			if element:
				stars = "*" * index
				params.extend([f"{stars}{arg}" for arg in (element if isinstance(element, list) else [element])])

		logger.trace("%s interface method: name %s, params %s", instance.__class__.__name__, method_name, params)
		doc = function.__doc__
		if doc:
			doc = dedent(doc).lstrip() or None

		methods[method_name] = {
			"name": method_name,
			"params": params,
			"args": args,
			"varargs": spec.varargs,
			"keywords": spec.varkw,
			"defaults": defaults,
			"deprecated": getattr(function, "deprecated", False),
			"alternative_method": getattr(function, "alternative_method", None),
			"doc": doc,
			"annotations": annotations,
		}

	return [methods[name] for name in sorted(list(methods.keys()))]


class OpsiconfdBackend(RPCHostMixin, RPCConfigMixin, RPCConfigStateMixin, RPCExtWIMMixin, RPCExtenderMixin, metaclass=Singleton):
	def __init__(self) -> None:
		super().__init__()
		self._interface = describe_interface(self)
		self._backend = get_client_backend()
		self._mysql = MySQLConnection()
		self._mysql.connect()
		self.method_names = [meth["name"] for meth in self._interface]
		self._acl: Dict[str, List[RPCACE]] = {}
		self._read_acl_file()

	def _read_acl_file(self) -> None:
		acl = read_acl_file(config.acl_file)
		for method_name in self.method_names:
			self._acl[method_name] = [ace for ace in acl if ace.method_re.match(method_name)]

	def _get_ace(self, method: str) -> List[RPCACE]:  # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
		session = contextvar_client_session.get()
		if not session or not session.user_store:
			raise BackendPermissionDeniedError("Invalid session")

		user_type = "user"
		if session.user_store.host:
			user_type = "client"
			if session.user_store.host.getType() in ("OpsiConfigserver", "OpsiDepotserver"):
				user_type = "depot"

		ace_list = []
		for ace in self._acl.get(method, []):
			if ace.type == "all":
				ace_list.append(ace)
			elif user_type == "user":  # pylint: disable=loop-invariant-statement
				if ace.type == "sys_user":
					if not ace.id or ace.id == session.user_store.username:
						ace_list.append(ace)
				elif ace.type == "sys_group":
					if not ace.id or ace.id in session.user_store.userGroups:
						ace_list.append(ace)
			elif ace.type == "self" and user_type in ("client", "depot"):  # pylint: disable=loop-invariant-statement
				kwargs = ace.__dict__
				kwargs["id"] = session.user_store.username
				ace_list.append(RPCACE(**kwargs))
			elif user_type == "client" and ace.type == "opsi_client":  # pylint: disable=loop-invariant-statement
				if not ace.id or ace.id == session.user_store.username:
					ace_list.append(ace)
			elif user_type == "depot" and ace.type == "opsi_depotserver":  # pylint: disable=loop-invariant-statement
				if not ace.id or ace.id == session.user_store.username:
					ace_list.append(ace)

		if ace_list:
			return ace_list

		raise BackendPermissionDeniedError("No permission")

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

	def server_createBackup(self) -> dict:  # pylint: disable=invalid-name
		self._check_role("admin")
		return create_backup()

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
