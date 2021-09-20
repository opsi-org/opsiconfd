# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
zeroconf
"""

import ipaddress
import socket
import asyncio
import netifaces
from aiozeroconf import ServiceInfo, Zeroconf

from . import __version__
from .logging import logger
from .config import config, FQDN
from .utils import get_ip_addresses
from .backend import get_backend

_zeroconf = None  # pylint: disable=invalid-name
_info = None  # pylint: disable=invalid-name

def _is_config_server():
	try:
		dispatch_backend = get_backend()
		while not hasattr(dispatch_backend, "_dispatchConfig"):
			dispatch_backend = dispatch_backend._backend  # pylint: disable=protected-access

		for _entry in dispatch_backend._dispatchConfig:  # pylint: disable=protected-access
			if "jsonrpc" in _entry[1]:
				return False
		return True
	except Exception as err:  # pylint: disable=broad-except
		logger.warning(err)
	return False

async def register_opsi_services():
	global _zeroconf, _info # pylint: disable=invalid-name,global-statement
	if not _is_config_server():
		return

	logger.devel("Register zeroconf service")

	if not _zeroconf:
		iface = None
		if str(config.interface) not in ("0.0.0.0", "::"):
			iface = config.interface
		address_family = [netifaces.AF_INET]  # pylint: disable=c-extension-no-member
		if str(config.interface) == "::":
			address_family.append(netifaces.AF_INET6)  # pylint: disable=c-extension-no-member
		_zeroconf = Zeroconf(asyncio.get_event_loop(), address_family=address_family, iface=iface)

	address = None
	address6 = None
	try:
		address = socket.getaddrinfo(FQDN, None, socket.AF_INET)[0][-1][0]
	except socket.error as err:
		logger.warning("Failed to get ipv4 address for '%s': %s", FQDN, err)
		for addr in get_ip_addresses():
			if (
				addr["family"] == "ipv4" and
				not addr["ip_address"].is_loopback
			):
				address = str(addr["ip_address"])
				break
	try:
		address6 = socket.getaddrinfo(FQDN, None, socket.AF_INET6)[0][-1][0]

	except socket.error as err:
		logger.debug("Failed to get ipv6 address for '%s': %s", FQDN, err)
		for addr in get_ip_addresses():
			if (
				addr["family"] == "ipv6" and
				not addr["ip_address"].is_loopback and
				not addr["ip_address"].is_link_local
			):
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
		properties={'version': __version__},
		server=FQDN + "."
	)
	await _zeroconf.register_service(_info)

async def unregister_opsi_services():
	global _zeroconf, _info # pylint: disable=invalid-name,global-statement,global-variable-not-assigned
	if not _zeroconf or not _info:
		return
	logger.notice("Unregister zeroconf service")
	await _zeroconf.unregister_service(_info)
	await _zeroconf.close()
