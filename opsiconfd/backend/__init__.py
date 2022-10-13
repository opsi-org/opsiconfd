# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd backend
"""


import threading
from time import sleep, time
from typing import Any, Callable, Dict, List

from OPSI.Backend.BackendManager import BackendManager  # type: ignore[import]
from OPSI.Backend.Manager.Dispatcher import _loadDispatchConfig  # type: ignore[import]
from OPSI.Backend.MySQL import MySQL  # type: ignore[import]
from requests.exceptions import ConnectionError as RequestsConnectionError
from starlette.concurrency import run_in_threadpool

from opsiconfd import contextvar_user_store
from opsiconfd.config import config
from opsiconfd.logging import logger
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


backend_manager_lock = threading.Lock()
backend_manager = None  # pylint: disable=invalid-name


def get_backend(timeout: int = -1) -> BackendManager:
	global backend_manager  # pylint: disable=invalid-name, global-statement
	with backend_manager_lock:
		if not backend_manager:
			start_time = time()
			while True:
				try:  # pylint: disable=loop-try-except-usage
					backend_manager = BackendManager(depotBackend=True)
					break
				except RequestsConnectionError as err:
					# JSONRPCBackend, config service connection error
					if timeout < 0:  # pylint: disable=loop-invariant-statement
						raise
					if timeout > 0 and time() - start_time >= timeout:  # pylint: disable=loop-invariant-statement,chained-comparison
						raise
					logger.warning("Failed to get backend, will retry in 10 seconds: %s", err)
					sleep(10)
	return backend_manager


async def async_backend_call(method: str, **kwargs: Any) -> Any:
	def _backend_call(method: str, **kwargs: Any) -> Any:
		meth = getattr(get_backend(), method)
		return meth(**kwargs)

	return await run_in_threadpool(_backend_call, method, **kwargs)


def get_server_role() -> str:
	for _method, backends in _loadDispatchConfig(config.dispatch_config_file):
		if "jsonrpc" in backends:
			return "depot"
	return "config"


def get_mysql() -> MySQL:
	backend = get_backend()
	while getattr(backend, "_backend", None):
		backend = backend._backend  # pylint: disable=protected-access
		if backend.__class__.__name__ == "BackendDispatcher":
			try:  # pylint: disable=loop-try-except-usage
				return backend._backends["mysql"]["instance"]._sql  # pylint: disable=protected-access
			except KeyError:
				# No mysql backend
				pass
	raise RuntimeError("MySQL backend not active")


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



