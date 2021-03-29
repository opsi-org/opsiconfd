# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import asyncio
import netifaces
from aiozeroconf import ServiceInfo, Zeroconf

from . import __version__
from .logging import logger
from .config import config
from .utils import get_ip_addresses, get_fqdn
from .backend import get_backend

_zeroconf = None  # pylint: disable=invalid-name
_info = None  # pylint: disable=invalid-name

async def async_register_opsi_service():
	global _zeroconf, _info # pylint: disable=invalid-name,global-statement
	logger.notice("Register zeroconf service")

	address = None
	address6 = None
	for addr in get_ip_addresses():
		if addr["family"] == "ipv4":
			address = addr["ip_address"].packed
		elif addr["family"] == "ipv6":
			address6 = addr["ip_address"].packed

	_info = ServiceInfo(
		"_opsics._tcp.local.",
		"opsi config service._opsics._tcp.local.",
		address=address,
		address6=address6,
		port=config.port,
		weight=0,
		priority=0,
		properties={'version': __version__},
		server=get_fqdn() + "."
	)
	await _zeroconf.register_service(_info)

async def async_unregister_opsi_service():
	global _zeroconf, _info # pylint: disable=invalid-name,global-statement
	if not _zeroconf or not _info:
		return
	logger.notice("Unregister zeroconf service")
	await _zeroconf.unregister_service(_info)
	await _zeroconf.close()

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

def register_opsi_services():
	if not _is_config_server():
		return
	global _zeroconf  # pylint: disable=invalid-name,global-statement
	loop = asyncio.get_event_loop()
	if not _zeroconf:
		iface = None
		if str(config.interface) not in ("0.0.0.0", "::"):
			iface = config.interface
		address_family = [netifaces.AF_INET]  # pylint: disable=c-extension-no-member
		if str(config.interface) == "::":
			address_family.append(netifaces.AF_INET6)  # pylint: disable=c-extension-no-member
		_zeroconf = Zeroconf(loop, address_family=address_family, iface=iface)
	loop.create_task(async_register_opsi_service())

def unregister_opsi_services():
	loop = asyncio.get_event_loop()
	loop.create_task(async_unregister_opsi_service())
