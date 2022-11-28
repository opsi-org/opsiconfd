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

from OPSI.Backend.Manager.Dispatcher import _loadDispatchConfig  # type: ignore[import]

from opsiconfd.config import config

if TYPE_CHECKING:
	from opsiconfd.backend.rpc.opsiconfd import (
		MySQLConnection,
		PrivateBackend,
		PublicBackend,
	)


def get_public_backend() -> PublicBackend:
	from .rpc.opsiconfd import PublicBackend  # pylint: disable=import-outside-toplevel

	return PublicBackend()


def get_private_backend() -> PrivateBackend:
	from .rpc.opsiconfd import PrivateBackend  # pylint: disable=import-outside-toplevel

	return PrivateBackend()


def get_server_role() -> str:
	# TODO:
	# for _method, backends in _loadDispatchConfig(config.dispatch_config_file):
	# 	if "jsonrpc" in backends:
	# 		return "depot"
	return "config"


def get_mysql() -> MySQLConnection:
	return get_public_backend()._mysql  # pylint: disable=protected-access


def execute_on_secondary_backends(method: str, backends: tuple = ("opsipxeconfd", "dhcpd"), **kwargs: Any) -> dict:
	result = {}
	backend = get_public_backend()
	# TODO:
	for backend_id in backends:
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
