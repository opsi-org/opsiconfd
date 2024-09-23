# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc
"""

from __future__ import annotations

import os
from threading import Lock
from typing import TYPE_CHECKING

from opsicommon.client.opsiservice import MessagebusListener, ServiceClient

from opsiconfd import __version__
from opsiconfd.config import config, get_depotserver_id, opsi_config

if TYPE_CHECKING:
	from opsiconfd.backend.mysql import MySQLConnection
	from opsiconfd.backend.rpc.main import ProtectedBackend, UnprotectedBackend

protected_backend = None
unprotected_backend = None
service_clients: dict[str, ServiceClient] = {}
service_clients_lock = Lock()


def reinit_backend() -> None:
	stop_service_clients()
	global protected_backend
	global unprotected_backend
	if protected_backend:
		protected_backend.reset_singleton()
		protected_backend = None
	if unprotected_backend:
		unprotected_backend.reset_singleton()
		unprotected_backend = None


def get_protected_backend() -> ProtectedBackend:
	global protected_backend
	if not protected_backend:
		from opsiconfd.backend.rpc.main import (
			ProtectedBackend,
		)

		protected_backend = ProtectedBackend()
	return protected_backend


def get_unprotected_backend() -> UnprotectedBackend:
	global unprotected_backend

	if not unprotected_backend:
		from opsiconfd.backend.rpc.main import (
			UnprotectedBackend,
		)

		unprotected_backend = UnprotectedBackend()
	return unprotected_backend


def get_mysql() -> MySQLConnection:
	return get_unprotected_backend()._mysql


def new_service_client(user_agent: str = "opsiconfd") -> ServiceClient:
	client_cert_file = None
	client_key_file = None
	client_key_password = None
	if (
		config.ssl_server_key
		and os.path.exists(config.ssl_server_key)
		and config.ssl_server_cert
		and os.path.exists(config.ssl_server_cert)
	):
		client_cert_file = config.ssl_server_cert
		client_key_file = config.ssl_server_key
		client_key_password = config.ssl_server_key_passphrase

	return ServiceClient(
		address=opsi_config.get("service", "url"),
		username=get_depotserver_id(),
		password=opsi_config.get("host", "key"),
		user_agent=user_agent,
		verify="strict_check",
		ca_cert_file=config.ssl_ca_cert,
		client_cert_file=client_cert_file,
		client_key_file=client_key_file,
		client_key_password=client_key_password,
		jsonrpc_create_objects=True,
	)


def get_service_client(name: str = "", register_messagebus_listener: MessagebusListener | None = None) -> ServiceClient:
	if config.shared_service_connection:
		name = ""
	with service_clients_lock:
		first_connection = not service_clients
		if name not in service_clients:
			from opsiconfd.worker import Worker

			user_agent = f"opsiconfd depotserver {__version__}"
			try:
				user_agent = f"{user_agent} worker {Worker.get_instance().id}"
			except RuntimeError:
				# No worker instance
				pass
			if name:
				user_agent = f"{user_agent} {name}"

			service_client = new_service_client(user_agent)
			if register_messagebus_listener:
				service_client.messagebus.register_messagebus_listener(register_messagebus_listener)
			service_client.messagebus.threaded_callbacks = False
			service_client.messagebus.reconnect_wait_min = 15
			service_client.messagebus.reconnect_wait_max = 30
			service_client.connect()
			if first_connection:
				service_client.fetch_ca_certs(force_write_ca_cert_file=True)
			service_client.connect_messagebus()
			service_clients[name] = service_client
		elif register_messagebus_listener:
			service_clients[name].messagebus.register_messagebus_listener(register_messagebus_listener)
			if service_clients[name].messagebus.connected:
				service_clients[name].messagebus._run_listener_callback(
					register_messagebus_listener, "messagebus_connection_established", messagebus=service_clients[name].messagebus
				)

		return service_clients[name]


def stop_service_clients() -> None:
	with service_clients_lock:
		for name in list(service_clients):
			service_clients[name].stop()
			del service_clients[name]
