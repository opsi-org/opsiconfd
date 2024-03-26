# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
zeroconf tests
"""

import asyncio

from aiozeroconf import (  # type: ignore[import]
	ServiceBrowser,
	ServiceStateChange,
	Zeroconf,
)

from opsiconfd import __version__
from opsiconfd.zeroconf import register_opsi_services, unregister_opsi_services

from .utils import get_config

services = {}


def on_service_state_change(zeroconf: Zeroconf, service_type: str, name: str, state_change: str) -> None:
	asyncio.ensure_future(on_service_state_change_process(zeroconf, service_type, name, state_change))


async def on_service_state_change_process(zeroconf: Zeroconf, service_type: str, name: str, state_change: str) -> None:
	# print("==================================================================================")
	# print(f"Service {name} of type {service_type} state changed: {state_change}")
	info = await zeroconf.get_service_info(service_type, name)
	# print(info)
	key = f"{info.server}:{info.port}"
	if state_change is ServiceStateChange.Added:
		services[key] = info
	elif state_change is ServiceStateChange.Removed:
		if key in services:
			del services[key]


async def test_register_opsi_services() -> None:
	services.clear()
	with get_config({"interface": "127.0.0.1"}) as config:
		loop = asyncio.get_running_loop()
		zeroconf = Zeroconf(loop)
		browser = ServiceBrowser(zeroconf, "_opsics._tcp.local.", handlers=[on_service_state_change])
		try:
			await asyncio.sleep(1)
			await register_opsi_services()
			await asyncio.sleep(1)

			assert len(services) == 1
			info = list(services.values())[0]
			assert info.port == config.port
			assert info.properties.get(b"version").decode("ascii") == __version__

			await asyncio.sleep(1)
			await unregister_opsi_services()
			await asyncio.sleep(5)
			assert len(services) == 0
		finally:
			browser.cancel()
			await zeroconf.close()
			await asyncio.sleep(1)
