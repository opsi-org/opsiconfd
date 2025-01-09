# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0


"""
worker check tests
"""


from datetime import datetime

from opsicommon.objects import OpsiClient
from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.worker import opsi_worker_capacity
from opsiconfd.check.common import CheckStatus, check_manager

from tests.utils import (  # noqa: F401
	cache_clear,
	clean_mysql,
	clean_redis,
	cleanup_checks,
)


def _prepare_client(number: int = 100) -> OpsiClient:  # noqa: F811
	clients = []
	now = datetime.now()

	for i in range(0, number):
		client = OpsiClient(id=f"test-check-client-{i}.opsi.test")
		client.lastSeen = now.strftime("%Y-%m-%d %H:%M:%S")
		client.setDefaults()
		clients.append(client)

	backend = get_unprotected_backend()
	backend.host_createObjects(clients)
	return client

def _delete_clients() -> None:  # noqa: F811
	backend = get_unprotected_backend()
	clients = backend.host_getObjects(type="OpsiClient")
	backend.host_deleteObjects(clients)


def test_worker_capacity_check() -> None:  # noqa: F811
	_prepare_client(number=1001)
	check_manager.register(opsi_worker_capacity)
	result = check_manager.get("opsi_worker_capacity").run(clear_cache=True)
	assert result.check_status == CheckStatus.ERROR
	_delete_clients()

	_prepare_client(number=601)
	check_manager.register(opsi_worker_capacity)
	result = check_manager.get("opsi_worker_capacity").run(clear_cache=True)
	assert result.check_status == CheckStatus.WARNING
	_delete_clients()

	_prepare_client(number=600)
	check_manager.register(opsi_worker_capacity)
	result = check_manager.get("opsi_worker_capacity").run(clear_cache=True)
	assert result.check_status == CheckStatus.OK
	_delete_clients()

	_prepare_client(number=599)
	check_manager.register(opsi_worker_capacity)
	result = check_manager.get("opsi_worker_capacity").run(clear_cache=True)
	assert result.check_status == CheckStatus.OK
	_delete_clients()