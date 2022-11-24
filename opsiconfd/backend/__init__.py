# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, Callable, Dict

from OPSI.Backend.BackendManager import BackendManager  # type: ignore[import]
from OPSI.Backend.Manager.Dispatcher import _loadDispatchConfig  # type: ignore[import]
from requests.exceptions import ConnectionError as RequestsConnectionError
from starlette.concurrency import run_in_threadpool

from opsiconfd import contextvar_user_store
from opsiconfd.config import config
from opsiconfd.logging import logger

if TYPE_CHECKING:
	from opsiconfd.backend.rpc.opsiconfd import (
		Backend,
		MySQLConnection,
		UnrestrictedBackend,
	)
	from opsiconfd.session import OPSISession, UserStore

BackendManager.default_config = {
	"dispatchConfigFile": config.dispatch_config_file,
	"backendConfigDir": config.backend_config_dir,
	"extensionConfigDir": config.extension_config_dir,
	"aclFile": None,  # No access control by default
	"hostControlBackend": True,
	"hostControlSafeBackend": True,
	"depotBackend": False,
	# every worker needs a database connection for full performance
	"connectionPoolSize": config.executor_workers,
	"max_log_size": round(config.max_log_size * 1000 * 1000),
	"keep_rotated_logs": config.keep_rotated_logs,
}

get_session_from_context: Callable | None = None  # pylint: disable=invalid-name


def get_session() -> OPSISession | None:
	global get_session_from_context  # pylint: disable=invalid-name, global-statement,global-variable-not-assigned
	if not get_session_from_context:
		from opsiconfd.session import (  # pylint: disable=import-outside-toplevel, redefined-outer-name
			get_session_from_context,
		)

	if get_session_from_context is None:
		return None
	return get_session_from_context()


def get_user_store() -> UserStore:
	session = get_session()
	if session:
		return session.user_store
	user_store = contextvar_user_store.get()
	if user_store:
		return user_store
	return UserStore()


def get_option_store() -> Dict[str, Any]:
	session = get_session()
	if not session:
		return {}
	return session.option_store


client_backend_manager_lock = threading.Lock()
client_backend_manager = None  # pylint: disable=invalid-name


def get_client_backend() -> BackendManager:
	global client_backend_manager  # pylint: disable=invalid-name, global-statement
	with client_backend_manager_lock:
		if not client_backend_manager:
			client_backend_manager = BackendManager(
				user_store=get_user_store, option_store=get_option_store, aclFile=config.acl_file, depotBackend=True
			)
			client_backend_manager.usage_count = 0
		client_backend_manager.usage_count += 1
	return client_backend_manager


def get_backend() -> Backend:
	from .rpc.opsiconfd import Backend  # pylint: disable=import-outside-toplevel
	return Backend()


def get_unrestricted_backend() -> UnrestrictedBackend:
	from .rpc.opsiconfd import (  # pylint: disable=import-outside-toplevel
		UnrestrictedBackend,
	)
	return UnrestrictedBackend()


def get_server_role() -> str:
	for _method, backends in _loadDispatchConfig(config.dispatch_config_file):
		if "jsonrpc" in backends:
			return "depot"
	return "config"


def get_mysql() -> MySQLConnection:
	return get_backend()._mysql  # pylint: disable=protected-access


def execute_on_secondary_backends(method: str, backends: tuple = ("opsipxeconfd", "dhcpd"), **kwargs: Any) -> dict:
	result = {}
	backend = get_client_backend()
	while getattr(backend, "_backend", None):
		backend = backend._backend  # pylint: disable=protected-access
		if backend.__class__.__name__ == "BackendDispatcher":
			for backend_id in backends:
				if backend_id not in backend._backends:  # pylint: disable=protected-access
					continue
				logger.info("Executing '%s' on secondary backend '%s'", method, backend_id)
				meth = getattr(backend._backends[backend_id]["instance"], method)  # pylint: disable=protected-access
				try:  # pylint: disable=loop-try-except-usage
					result[backend_id] = {"data": meth(**kwargs), "error": None}  # pylint: disable=loop-invariant-statement
				except Exception as err:  # pylint: disable=broad-except
					result[backend_id] = {"data": None, "error": err}  # pylint: disable=loop-invariant-statement
				backend._backends[backend_id]["instance"].backend_exit()  # pylint: disable=protected-access
	return result
