# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
zeroconf
"""

import asyncio
import ipaddress
import socket

import netifaces  # type: ignore[import]
from aiozeroconf import ServiceInfo, Zeroconf  # type: ignore[import]

from opsiconfd import __version__
from opsiconfd.config import FQDN, config, get_server_role
from opsiconfd.logging import logger
from opsiconfd.utils import get_ip_addresses

_zeroconf = None
_info = None


async def register_opsi_services() -> None:
	global _zeroconf, _info
	if get_server_role() != "configserver":
		return

	logger.info("Register zeroconf service")

	if not _zeroconf:
		iface = None
		if str(config.interface) not in ("0.0.0.0", "::"):
			if_address = ipaddress.ip_address(config.interface)
			iface = netifaces.interfaces()[0]
			for _iface in netifaces.interfaces():
				for addr_type in (netifaces.AF_INET, netifaces.AF_INET6):
					for addr in netifaces.ifaddresses(_iface).get(  # type: ignore
						addr_type, []
					):
						try:
							if if_address == ipaddress.ip_address(addr["addr"]):
								iface = _iface
						except ValueError:
							continue

		address_family = [netifaces.AF_INET]
		if isinstance(config.interface, ipaddress.IPv6Address):
			address_family.append(netifaces.AF_INET6)
		_zeroconf = Zeroconf(asyncio.get_running_loop(), address_family=address_family, iface=iface)

	address = None
	address6 = None
	try:
		address = socket.getaddrinfo(FQDN, None, socket.AF_INET)[0][-1][0]
	except socket.error as err:
		logger.warning("Failed to get ipv4 address for '%s': %s", FQDN, err)
		for addr in get_ip_addresses():
			if addr["family"] == "ipv4" and not addr["ip_address"].is_loopback:
				address = str(addr["ip_address"])
				break

	try:
		address6 = socket.getaddrinfo(FQDN, None, socket.AF_INET6)[0][-1][0]
	except socket.error as err:
		logger.debug("Failed to get ipv6 address for '%s': %s", FQDN, err)
		for addr in get_ip_addresses():
			if addr["family"] == "ipv6" and not addr["ip_address"].is_loopback and not addr["ip_address"].is_link_local:
				address6 = str(addr["ip_address"])
				break

	logger.info("Using the following ip addresses for zeroconf: ipv4=%s, ipv6=%s", address, address6)

	_info = ServiceInfo(
		"_opsics._tcp.local.",
		"opsi config service._opsics._tcp.local.",
		address=ipaddress.ip_address(address).packed if address else None,
		address6=ipaddress.ip_address(address6).packed if address6 else None,
		port=config.port,
		weight=0,
		priority=0,
		properties={"version": __version__},
		server=FQDN + ".",
	)
	await _zeroconf.register_service(_info)


async def unregister_opsi_services() -> None:
	global _zeroconf, _info
	if not _zeroconf or not _info:
		return
	logger.notice("Unregister zeroconf service")
	await _zeroconf.unregister_service(_info)
	await _zeroconf.close()
