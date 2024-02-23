# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods dynamic depot
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

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
		from OPSI.Util.Ping import ping
		from urllib.parse import urlparse

		latency = []
		for depot in depots:
			if not depot.depotWebdavUrl:
				logger.info("Skipping %r because depotWebdavUrl is missing", depot)
				continue

			try:
				host = urlparse(depot.depotWebdavUrl).hostname
				# To increase the timeout (in seconds) for the ping you
				# can implement it in the following way:
				#  depotLatency = ping(host, timeout=5)
				logger.info("Ping %r (host: %r)", depot, host)
				depotLatency = ping(host)

				if depotLatency is None:
					logger.info("Ping to depot %s timed out.", depot)
				else:
					logger.info("Latency of depot %s: %0.3f ms", depot, depotLatency * 1000)
					latency.append((depot, depotLatency))
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
		logger.notice("Depot with lowest latency: %r (%0.3f ms)", selectedDepot, minLatency * 1000)
		return selectedDepot
'''

DEPOT_SELECTION_ALGORITHM_BY_MASTER_DEPOT_AND_LATENCY = f"""
def selectDepot(clientConfig, masterDepot, alternativeDepots=[]):
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
	{SHOW_DEPOT_INFO_FUNCTION}

	showDepotInfo()

	import random
	selectedDepot = random.choice([masterDepot] + alternativeDepots)
	logger.info("The depot %r was selected at random", selectedDepot)
	return selectedDepot
"""


DEPOT_SELECTION_ALGORITHM_BY_NETWORK_ADDRESS = f"""
def selectDepot(clientConfig, masterDepot, alternativeDepots=[]):
	{SHOW_DEPOT_INFO_FUNCTION}

	showDepotInfo()

	if not alternativeDepots:
		return masterDepot

	import ipaddress
	try:
		from opsicommon.utils import ip_address_in_network
	except ImportError:
		from OPSI.Util import ipAddressInNetwork as ip_address_in_network

	for depot in sorted([d for d in ([masterDepot] + alternativeDepots) if d.networkAddress], key=lambda x: ipaddress.ip_network(x.networkAddress).prefixlen, reverse=True):
		if ip_address_in_network(clientConfig['ipAddress'], depot.networkAddress):
			logger.notice("Choosing depot with network address %r for client address %r", depot.networkAddress, clientConfig['ipAddress'])
			return depot
		logger.info("IP %s does not match networkAddress %s of depot %s", clientConfig['ipAddress'], depot.networkAddress, depot)

	return masterDepot
"""


class RPCExtDynamicDepotMixin(Protocol):
	@rpc_method(check_acl=False)
	def getDepotSelectionAlgorithmByMasterDepotAndLatency(self) -> str:
		return DEPOT_SELECTION_ALGORITHM_BY_MASTER_DEPOT_AND_LATENCY

	@rpc_method(check_acl=False)
	def getDepotSelectionAlgorithmByLatency(self) -> str:
		return DEPOT_SELECTION_ALGORITHM_BY_LATENCY

	@rpc_method(check_acl=False)
	def getDepotSelectionAlgorithmByRandom(self) -> str:
		return DEPOT_SELECTION_ALGORITHM_BY_RANDOM

	@rpc_method(check_acl=False)
	def getDepotSelectionAlgorithmByNetworkAddress(self) -> str:
		return DEPOT_SELECTION_ALGORITHM_BY_NETWORK_ADDRESS

	@rpc_method(check_acl=False)
	def getDepotSelectionAlgorithmByNetworkAddressBestMatch(self) -> str:
		# Legacy method, same as getDepotSelectionAlgorithmByNetworkAddress
		return DEPOT_SELECTION_ALGORITHM_BY_NETWORK_ADDRESS

	@rpc_method(check_acl=False)
	def getDepotSelectionAlgorithm(self: BackendProtocol) -> str:
		"""Returns the selected depot selection algorithm."""
		mode = "network_address"
		configs = self.config_getObjects(id="clientconfig.depot.selection_mode")
		if configs and configs[0].defaultValues:
			mode = configs[0].defaultValues[0]

		if mode == "master_and_latency":
			return self.getDepotSelectionAlgorithmByMasterDepotAndLatency()
		if mode == "latency":
			return self.getDepotSelectionAlgorithmByLatency()
		if mode in ("network_address", "network_address_best_match"):
			return self.getDepotSelectionAlgorithmByNetworkAddress()
		if mode == "random":
			return self.getDepotSelectionAlgorithmByRandom()

		logger.error("Invalid 'clientconfig.depot.selection_mode': %r", mode)
		return self.getDepotSelectionAlgorithmByNetworkAddress()
