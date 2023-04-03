# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc
"""

from __future__ import annotations

from threading import Lock
from typing import TYPE_CHECKING, Any

from opsicommon.client.opsiservice import ServiceClient  # type: ignore[import]

from opsiconfd import __version__
from opsiconfd.config import config, get_depotserver_id, opsi_config

if TYPE_CHECKING:
	from opsiconfd.backend.mysql import MySQLConnection
	from opsiconfd.backend.rpc.main import ProtectedBackend, UnprotectedBackend

protected_backend = None  # pylint: disable=invalid-name
unprotected_backend = None  # pylint: disable=invalid-name
service_clients = {}  # pylint: disable=invalid-name
service_clients_lock = Lock()


def get_protected_backend() -> ProtectedBackend:
	global protected_backend  # pylint: disable=invalid-name,global-statement
	if not protected_backend:
		from opsiconfd.backend.rpc.main import (  # pylint: disable=import-outside-toplevel
			ProtectedBackend,
		)

		protected_backend = ProtectedBackend()
	return protected_backend


def get_unprotected_backend() -> UnprotectedBackend:
	global unprotected_backend  # pylint: disable=invalid-name,global-statement
	if not unprotected_backend:
		from opsiconfd.backend.rpc.main import (  # pylint: disable=import-outside-toplevel
			UnprotectedBackend,
		)

		unprotected_backend = UnprotectedBackend()
	return unprotected_backend


def get_mysql() -> MySQLConnection:
	return get_unprotected_backend()._mysql  # pylint: disable=protected-access


def new_service_client(user_agent: str = "opsiconfd") -> ServiceClient:
	return ServiceClient(
		address=opsi_config.get("service", "url"),
		username=get_depotserver_id(),
		password=opsi_config.get("host", "key"),
		user_agent=user_agent,
		verify="strict_check",
		ca_cert_file=config.ssl_ca_cert,
		jsonrpc_create_objects=True,
	)


def get_service_client(name: str = "") -> ServiceClient:
	with service_clients_lock:
		if name not in service_clients:
			from opsiconfd.worker import Worker  # pylint: disable=import-outside-toplevel

			user_agent = f"opsiconfd depotserver {__version__}"
			try:
				user_agent = f"{user_agent} worker {Worker.get_instance().id}"
			except RuntimeError:
				# No worker instance
				pass
			if name:
				user_agent = f"{user_agent} {name}"

			service_client = new_service_client(user_agent)
			service_client.messagebus.threaded_callbacks = False
			service_client.messagebus.reconnect_wait_min = 15
			service_client.messagebus.reconnect_wait_max = 30
			service_client.connect()
			service_client.connect_messagebus()
			service_clients[name] = service_client
		return service_clients[name]


def execute_on_secondary_backends(
	method: str, backends: tuple = ("opsipxeconfd", "dhcpd"), **kwargs: Any  # pylint: disable=unused-argument
) -> dict:
	result: dict[str, Any] = {}
	# backend = get_protected_backend()
	# TODO:
	for _backend_id in backends:
		pass
		# if backend_id not in backend._backends:  # pylint: disable=protected-access
		# 	continue
		# logger.info("Executing '%s' on secondary backend '%s'", method, backend_id)
		# meth = getattr(backend._backends[backend_id]["instance"], method)  # pylint: disable=protected-access
		# try:
		# 	result[backend_id] = {"data": meth(**kwargs), "error": None}
		# except Exception as err:  # pylint: disable=broad-except
		# 	result[backend_id] = {"data": None, "error": err}
		# backend._backends[backend_id]["instance"].backend_exit()  # pylint: disable=protected-access
	return result
