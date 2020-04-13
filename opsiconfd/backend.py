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

#from OPSI.Backend.Base.Backend import BackendOptions
#from OPSI.Backend.Manager.AccessControl import UserStore
from OPSI.Backend.BackendManager import BackendManager

from .config import config

backend_config =  {
	'dispatchConfigFile': config.dispatch_config_file,
	'backendConfigDir': config.backend_config_dir,
	'extensionConfigDir': config.extension_config_dir,
	'aclFile': config.acl_file,
	###########'adminNetworks': config.admin_networks,
	'hostControlBackend': True,
	'hostControlSafeBackend': True,
	'depotBackend' : True,
	# every worker needs a database connection for full performance
	'connectionpoolsize': config.executor_workers
}

get_session_from_context = None
def get_session():
	global get_session_from_context
	if not get_session_from_context:
		from .session import get_session_from_context
	return get_session_from_context()

def get_user_store():
	return get_session().user_store

def get_option_store():
	return get_session().option_store

client_backend_manager_lock = threading.Lock()
client_backend_manager = None
def get_client_backend():
	global client_backend_manager
	with client_backend_manager_lock:
		if not client_backend_manager:
			backend_config["user_store"] = get_user_store
			backend_config["option_store"] = get_option_store
			client_backend_manager = BackendManager(**backend_config)
	return client_backend_manager

backend_manager_lock = threading.Lock()
backend_manager = None
def get_backend():
	global backend_manager
	with backend_manager_lock:
		if not backend_manager:
			bc = dict(backend_config)
			if "aclFile" in bc:
				del bc["aclFile"]
			backend_manager = BackendManager(**bc)
	return backend_manager

backend_interface = None
def get_backend_interface():
	global backend_interface
	if backend_interface is None:
		backend_interface = get_client_backend().backend_getInterface()
	return backend_interface
