# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.ext_dynamic_depot
"""

from opsicommon.logging import LOG_DEBUG, get_logger, use_logging_config
from opsicommon.objects import OpsiClient, OpsiDepotserver

from tests.utils import (  # noqa: F401
	UnprotectedBackend,
	backend,
)

logger = get_logger()


async def test_algorithms(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	client = OpsiClient(id="client1.opsi.test")
	depot1 = OpsiDepotserver(
		id="depot1.opsi.test",
		networkAddress="10.100.1.0/255.255.255.0",
		depotWebdavUrl="https://localhost:4447/depot",
	)
	depot2 = OpsiDepotserver(
		id="depot2.opsi.test",
		networkAddress="10.1.0.0/16",
		depotWebdavUrl="https://localhost:4447/depot",
		masterDepotId="depot1.opsi.test",
	)
	depot3 = OpsiDepotserver(
		id="depot3.opsi.test",
		networkAddress="300.400.500.600",
		depotWebdavUrl="https://unavail:4447/depot",
		masterDepotId="depot1.opsi.test",
	)
	depot4 = OpsiDepotserver(
		id="depot4.opsi.test",
		networkAddress="10.1.1.0/24",
		depotWebdavUrl="https://localhost:4447/depot",
	)
	depot5 = OpsiDepotserver(
		id="depot4.opsi.test",
		networkAddress=None,
		depotWebdavUrl="https://unavail:4447/depot",
	)
	clientConfig = {
		"clientId": client.id,
		"opsiHostKey": client.opsiHostKey,
		"ipAddress": "10.1.1.1",
		"netmask": "255.255.155.0",
		"defaultGateway": "10.1.1.254",
	}

	code = backend.getDepotSelectionAlgorithmByMasterDepotAndLatency()
	current_locals = locals()
	exec(code, None, current_locals)
	selectDepot = current_locals["selectDepot"]
	with use_logging_config(stderr_level=LOG_DEBUG):
		selectedDepot = selectDepot(clientConfig=clientConfig, masterDepot=depot1, alternativeDepots=[depot2, depot3, depot4, depot5])
	assert selectedDepot in [depot1, depot2]

	code = backend.getDepotSelectionAlgorithmByLatency()
	current_locals = locals()
	exec(code, None, current_locals)
	selectDepot = current_locals["selectDepot"]
	with use_logging_config(stderr_level=LOG_DEBUG):
		selectedDepot = selectDepot(clientConfig=clientConfig, masterDepot=depot1, alternativeDepots=[depot2, depot3, depot4, depot5])
	assert selectedDepot in [depot1, depot2, depot4]

	code = backend.getDepotSelectionAlgorithmByNetworkAddress()
	current_locals = locals()
	exec(code, None, current_locals)
	selectDepot = current_locals["selectDepot"]
	with use_logging_config(stderr_level=LOG_DEBUG):
		selectedDepot = selectDepot(clientConfig=clientConfig, masterDepot=depot1, alternativeDepots=[depot2, depot3, depot4, depot5])
	assert selectedDepot == depot4

	code = backend.getDepotSelectionAlgorithmByRandom()
	current_locals = locals()
	exec(code, None, current_locals)
	selectDepot = current_locals["selectDepot"]
	with use_logging_config(stderr_level=LOG_DEBUG):
		selectedDepot = selectDepot(clientConfig=clientConfig, masterDepot=depot1, alternativeDepots=[depot2, depot3, depot4, depot5])
	assert selectedDepot in [depot1, depot2, depot3, depot4, depot5]
