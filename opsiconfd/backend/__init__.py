# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opsicommon.client.opsiservice import ServiceClient  # type: ignore[import]

from opsiconfd.config import config, get_depotserver_id, opsi_config

if TYPE_CHECKING:
	from opsiconfd.backend.mysql import MySQLConnection
	from opsiconfd.backend.rpc.main import ProtectedBackend, UnprotectedBackend

protected_backend = None  # pylint: disable=invalid-name
unprotected_backend = None  # pylint: disable=invalid-name
service_client = None  # pylint: disable=invalid-name


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


def get_service_client() -> ServiceClient:
	global service_client  # pylint: disable=invalid-name,global-statement
	if not service_client:
		service_client = ServiceClient(
			address=opsi_config.get("service", "url"),
			username=get_depotserver_id(),
			password=opsi_config.get("host", "key"),
			verify="uib_opsi_ca",
			ca_cert_file=config.ssl_ca_cert,
			jsonrpc_create_objects=True,
		)
		service_client.connect()
		service_client.connect_messagebus()
	return service_client


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
		# try:  # pylint: disable=loop-try-except-usage
		# 	result[backend_id] = {"data": meth(**kwargs), "error": None}  # pylint: disable=loop-invariant-statement
		# except Exception as err:  # pylint: disable=broad-except
		# 	result[backend_id] = {"data": None, "error": err}  # pylint: disable=loop-invariant-statement
		# backend._backends[backend_id]["instance"].backend_exit()  # pylint: disable=protected-access
	return result
