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
:author: Jan Schneider <j.schneider@uib.de>
:license: GNU Affero General Public License version 3
"""


import threading

from OPSI.Backend import no_export
from OPSI.Backend.BackendManager import BackendManager
from OPSI.Backend.Manager.Dispatcher import _loadDispatchConfig
from OPSI.Backend.Base.Backend import describeInterface

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
		backend_interface = get_client_backend().backend_getInterface()
		backend_interface.extend(opsiconfd_backend.get_interface())
	return backend_interface

def get_server_role():
	for (_method, backends) in _loadDispatchConfig(config.dispatch_config_file):
		if "jsonrpc" in backends:
			return "depot"
	return "config"


class OpsiconfdBackend(metaclass=Singleton):
	@no_export
	def get_interface(self):
		return describeInterface(self)

	def backend_getOpsiCACert(self):  # pylint: disable=invalid-name,no-self-use
		from .ssl import get_ca_cert_as_pem  # pylint: disable=import-outside-toplevel
		return get_ca_cert_as_pem()

	def host_getTLSCertificate(self, hostId):  # pylint: disable=invalid-name
		pass

opsiconfd_backend = OpsiconfdBackend()
