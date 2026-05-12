# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
rpc methods dynamic depot
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from opsi.opsi.service.model.type import to_host_id

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol

SHOW_DEPOT_INFO_FUNCTION = """
	def showDepotInfo():
		logger.info("Choosing depot from list of depots:")
		logger.info("   Master depot: %r (networkAddress=%r)", masterDepot.id, masterDepot.networkAddress)
		for alternativeDepot in alternativeDepots:
			logger.info(
				"   Alternative depot: %r (masterDepotId=%r, networkAddress=%r)",
				alternativeDepot.id, alternativeDepot.masterDepotId, alternativeDepot.networkAddress
			)
"""

GET_LATENCY_INFORMATION_FUNCTION = '''
	def getLatencyInformation(depots):
		"""
		Pings the given depots and returns the latency information in a list of tuples with depot as first and the latency as second item.

		Depots that can't be reached in time will not be included.
		"""
		from urllib.parse import urlparse
		new_ping = False
		try:
			from opsi.network import ping
			new_ping = True
		except ImportError:
			try:
				from opsi_legacy.Util.Ping import ping
			except ImportError:
				from OPSI.Util.Ping import ping

		latency = []
		for depot in depots:
			if not depot.depotWebdavUrl:
				logger.info("Skipping %r because depotWebdavUrl is missing", depot.id)
				continue

			try:
				host = urlparse(depot.depotWebdavUrl).hostname
				logger.info("Ping %r (host: %r)", depot.id, host)

				depot_latency = None
				if new_ping:
					ping_result = ping(host, timeout=2, count=2)
					logger.info("Ping result for depot %r: %r", depot.id, ping_result)
					depot_latency = ping_result.rtt_avg
				else:
					depot_latency = ping(host, timeout=2)

				if depot_latency is None:
					logger.info("Ping to depot %s timed out.", depot.id)
				else:
					logger.info("Latency of depot %s: %0.3f ms", depot.id, depot_latency * 1000)
					latency.append((depot, depot_latency))
			except Exception as err:
				logger.warning(err)

		return latency
'''

GET_DEPOT_WITH_LOWEST_LATENCY_FUNCTION = '''
	def getDepotWithLowestLatency(latency):
		"""
		Given a list of tuples with depot as first and latency as second item it will return the depot with the lowest latency.

		Will return None if no depot can be determined.
		"""
		if not latency:
			return None

		selectedDepot, minLatency = sorted(latency, key=lambda x: x[1])[0]
		logger.notice("Depot with lowest latency: %r (%0.3f ms)", selectedDepot.id, minLatency * 1000)
		return selectedDepot
'''

DEPOT_SELECTION_ALGORITHM_BY_MASTER_DEPOT_AND_LATENCY = f"""
def selectDepot(clientConfig, masterDepot, alternativeDepots=[]):
	logger.notice("Choosing depot based on master depot and latency")
	{GET_LATENCY_INFORMATION_FUNCTION}
	{GET_DEPOT_WITH_LOWEST_LATENCY_FUNCTION}
	{SHOW_DEPOT_INFO_FUNCTION}

	showDepotInfo()

	if not alternativeDepots:
		return masterDepot

	depots = [masterDepot] + [d for d in alternativeDepots if d.masterDepotId == masterDepot.id]
	if len(depots) == 1:
		return masterDepot

	depotsWithLatency = getLatencyInformation(depots)
	depotWithLowestLatency = getDepotWithLowestLatency(depotsWithLatency)
	if depotWithLowestLatency:
		return depotWithLowestLatency

	logger.info("No depot with lowest latency, falling back to master depot.")
	return masterDepot
"""

DEPOT_SELECTION_ALGORITHM_BY_LATENCY = f"""
def selectDepot(clientConfig, masterDepot, alternativeDepots=[]):
	logger.notice("Choosing depot based on latency")
	{GET_LATENCY_INFORMATION_FUNCTION}
	{GET_DEPOT_WITH_LOWEST_LATENCY_FUNCTION}
	{SHOW_DEPOT_INFO_FUNCTION}

	showDepotInfo()

	if not alternativeDepots:
		return masterDepot

	depotsWithLatency = getLatencyInformation([masterDepot] + alternativeDepots)
	depotWithLowestLatency = getDepotWithLowestLatency(depotsWithLatency)
	if depotWithLowestLatency:
		return depotWithLowestLatency

	logger.info("No depot with lowest latency, falling back to master depot.")
	return masterDepot
"""

DEPOT_SELECTION_ALGORITHM_BY_RANDOM = f"""
def selectDepot(clientConfig, masterDepot, alternativeDepots=[]):
	logger.notice("Choosing depot at random")
	{SHOW_DEPOT_INFO_FUNCTION}

	showDepotInfo()

	import random
	selectedDepot = random.choice([masterDepot] + alternativeDepots)
	logger.info("The depot %r was selected at random", selectedDepot)
	return selectedDepot
"""


DEPOT_SELECTION_ALGORITHM_BY_NETWORK_ADDRESS = f"""
def selectDepot(clientConfig, masterDepot, alternativeDepots=[]):
	logger.notice("Choosing depot based on network address")
	{SHOW_DEPOT_INFO_FUNCTION}

	showDepotInfo()

	if not alternativeDepots:
		return masterDepot

	import ipaddress
	try:
		from opsi.network import ip_address_in_network
	except ImportError:
		try:
			from opsicommon.utils import ip_address_in_network
		except ImportError:
			from OPSI.Util import ipAddressInNetwork as ip_address_in_network

	for depot in sorted([d for d in ([masterDepot] + alternativeDepots) if d.networkAddress], key=lambda x: ipaddress.ip_network(x.networkAddress).prefixlen, reverse=True):
		if ip_address_in_network(clientConfig['ipAddress'], depot.networkAddress):
			logger.notice("Choosing depot %r with network address %r for client address %r", depot.id, depot.networkAddress, clientConfig['ipAddress'])
			return depot
		logger.info("IP %s does not match networkAddress %s of depot %s", clientConfig['ipAddress'], depot.networkAddress, depot.id)

	return masterDepot
"""


class RPCExtDynamicDepotMixin(Protocol):
	@rpc_method(check_acl=False, deprecated=True, alternative_method="depot_getDepotSelectionAlgorithm")
	def getDepotSelectionAlgorithm(self: BackendProtocol) -> str:
		return self.depot_getDepotSelectionAlgorithm()

	@rpc_method(check_acl=False)
	def depot_getDepotSelectionAlgorithm(self: BackendProtocol, clientId: str | None = None) -> str:
		"""Returns the selected depot selection algorithm."""
		clientId = to_host_id(clientId) if clientId else None
		logger.debug("Getting depot selection algorithm for client %r", clientId)
		config_id = "clientconfig.depot.selection_mode"

		mode = ""
		if clientId:
			values = self.configState_getValues(config_ids=[config_id], object_ids=[clientId], with_defaults=True)
			mode = (values.get(clientId, {}).get(config_id) or [""])[0]
			if mode:
				logger.info("Using depot selection mode configured for client %r: %r", clientId, mode)
		if not mode:
			configs = self.config_getObjects(id="clientconfig.depot.selection_mode")
			if configs and configs[0].defaultValues and configs[0].defaultValues[0]:
				mode = configs[0].defaultValues[0]
				logger.info("Using depot selection mode configured as default: %r", mode)
		if not mode:
			mode = "network_address"
			logger.info("No depot selection mode configured, falling back to default '%s'", mode)

		if mode == "master_and_latency":
			return DEPOT_SELECTION_ALGORITHM_BY_MASTER_DEPOT_AND_LATENCY
		if mode == "latency":
			return DEPOT_SELECTION_ALGORITHM_BY_LATENCY
		if mode in ("network_address", "network_address_best_match"):
			return DEPOT_SELECTION_ALGORITHM_BY_NETWORK_ADDRESS
		if mode == "random":
			return DEPOT_SELECTION_ALGORITHM_BY_RANDOM

		logger.error("Invalid '%s': %r", config_id, mode)
		return DEPOT_SELECTION_ALGORITHM_BY_NETWORK_ADDRESS
