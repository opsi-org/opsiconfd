# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.ext_dynamic_depot
"""

from opsi.logging import LOG_DEBUG, get_logger, use_logging_config
from opsi.opsi.service.model.object import ConfigState, OpsiClient, OpsiDepotserver, UnicodeConfig

from tests.utils import OpsiconfdTestClient, UnprotectedBackend, backend, clean_mysql, test_client  # noqa: F401

logger = get_logger()


async def test_algorithms(
	backend: UnprotectedBackend,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
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
		id="depot5.opsi.test",
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

	selection_mode_config = UnicodeConfig(
		id="clientconfig.depot.selection_mode",
		description="Depot selection mode.",
		possibleValues=["master_and_latency", "latency", "network_address", "random"],
		defaultValues=["network_address"],
		editable=False,
		multiValue=False,
	)
	selection_mode_config_state = ConfigState(
		configId=selection_mode_config.id,
		objectId=client.id,
		values=[],
	)
	backend.host_createObjects([client, depot1, depot2, depot4, depot5])
	backend.config_createObjects([selection_mode_config])
	backend.configState_createObjects([selection_mode_config_state])

	assert client.opsiHostKey
	test_client.auth = (client.id, client.opsiHostKey)

	def get_code(_backend: UnprotectedBackend | OpsiconfdTestClient, client_id: str | None = None) -> str:
		if isinstance(_backend, UnprotectedBackend):
			return _backend.depot_getDepotSelectionAlgorithm(clientId=client_id)
		res = test_client.jsonrpc20("depot_getDepotSelectionAlgorithm", params={"clientId": client_id})
		assert "error" not in res
		return res["result"]

	# Test default and client specific config values
	selection_mode_config.defaultValues = ["random"]
	selection_mode_config_state.values = ["network_address"]
	backend.config_createObjects([selection_mode_config])
	backend.configState_createObjects([selection_mode_config_state])

	for _backend in backend, test_client:
		for client_id in None, client.id:
			code = get_code(_backend, client_id)
			if client_id:
				assert 'logger.notice("Choosing depot based on network address")' in code
			else:
				assert 'logger.notice("Choosing depot at random")' in code

	# Reset to empty values for further tests
	selection_mode_config.defaultValues = []
	selection_mode_config_state.values = []
	backend.config_createObjects([selection_mode_config])
	backend.configState_createObjects([selection_mode_config_state])

	# Test all algorithms
	selection_mode_config.defaultValues = ["master_and_latency"]
	backend.config_createObjects([selection_mode_config])
	for _backend in backend, test_client:
		code = get_code(_backend)
		current_locals = locals()
		exec(code, None, current_locals)
		selectDepot = current_locals["selectDepot"]
		with use_logging_config(stderr_level=LOG_DEBUG):
			selectedDepot = selectDepot(clientConfig=clientConfig, masterDepot=depot1, alternativeDepots=[depot2, depot3, depot4, depot5])
		assert selectedDepot in [depot1, depot2]

	selection_mode_config.defaultValues = ["latency"]
	backend.config_createObjects([selection_mode_config])
	for _backend in backend, test_client:
		code = get_code(_backend)
		current_locals = locals()
		exec(code, None, current_locals)
		selectDepot = current_locals["selectDepot"]
		with use_logging_config(stderr_level=LOG_DEBUG):
			selectedDepot = selectDepot(clientConfig=clientConfig, masterDepot=depot1, alternativeDepots=[depot2, depot3, depot4, depot5])
		assert selectedDepot in [depot1, depot2, depot4]

	selection_mode_config.defaultValues = ["network_address"]
	backend.config_createObjects([selection_mode_config])
	for _backend in backend, test_client:
		code = get_code(_backend)
		current_locals = locals()
		exec(code, None, current_locals)
		selectDepot = current_locals["selectDepot"]
		with use_logging_config(stderr_level=LOG_DEBUG):
			selectedDepot = selectDepot(clientConfig=clientConfig, masterDepot=depot1, alternativeDepots=[depot2, depot3, depot4, depot5])
		assert selectedDepot == depot4

	selection_mode_config.defaultValues = ["random"]
	backend.config_createObjects([selection_mode_config])
	for _backend in backend, test_client:
		for client_id in None, client.id:
			code = get_code(_backend, client_id)
			current_locals = locals()
			exec(code, None, current_locals)
			selectDepot = current_locals["selectDepot"]
			with use_logging_config(stderr_level=LOG_DEBUG):
				selectedDepot = selectDepot(
					clientConfig=clientConfig, masterDepot=depot1, alternativeDepots=[depot2, depot3, depot4, depot5]
				)
			assert selectedDepot in [depot1, depot2, depot3, depot4, depot5]
