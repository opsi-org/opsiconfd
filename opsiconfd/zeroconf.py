# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""

import asyncio
import netifaces
from aiozeroconf import ServiceInfo, Zeroconf

from . import __version__
from .logging import logger
from .config import config
from .utils import get_ip_addresses, get_fqdn

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

def register_opsi_services():
	global _zeroconf # pylint: disable=invalid-name,global-statement
	loop = asyncio.get_event_loop()
	if not _zeroconf:
		iface = None
		if str(config.interface) not in ("0.0.0.0", "::"):
			iface = config.interface
		address_family = [netifaces.AF_INET] # pylint: disable=c-extension-no-member
		if str(config.interface) == "::":
			address_family.append(netifaces.AF_INET6) # pylint: disable=c-extension-no-member
		_zeroconf = Zeroconf(loop, address_family=address_family, iface=iface)
	loop.create_task(async_register_opsi_service())

def unregister_opsi_services():
	loop = asyncio.get_event_loop()
	loop.create_task(async_unregister_opsi_service())
