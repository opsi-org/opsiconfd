# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
zeroconf tests
"""

import asyncio
import socket
import pytest
from aiozeroconf import ServiceBrowser, ServiceStateChange, Zeroconf

from opsiconfd import __version__
from opsiconfd.zeroconf import register_opsi_services, unregister_opsi_services

from .utils import get_config  # pylint: disable=unused-import

services = {}


def on_service_state_change(zeroconf, service_type, name, state_change):
	asyncio.ensure_future(on_service_state_change_process(zeroconf, service_type, name, state_change))


async def on_service_state_change_process(zeroconf, service_type, name, state_change):
	# print("==================================================================================")
	# print(f"Service {name} of type {service_type} state changed: {state_change}")
	info = await zeroconf.get_service_info(service_type, name)
	# print(info)
	key = f"{socket.inet_ntoa(info.address)}:{info.port}"
	if state_change is ServiceStateChange.Added:
		services[key] = info
	elif state_change is ServiceStateChange.Removed:
		if key in services:
			del services[key]

@pytest.mark.xfail(reason="Zeroconf test not always working in CI")
async def test_register_opsi_services():
	services.clear()
	with get_config({"interface": "127.0.0.1"}) as config:
		loop = asyncio.get_running_loop()
		zeroconf = Zeroconf(loop)
		browser = ServiceBrowser(zeroconf, "_opsics._tcp.local.", handlers=[on_service_state_change])
		await asyncio.sleep(1)
		await register_opsi_services()
		await asyncio.sleep(1)

		assert len(services) == 1
		info = list(services.values())[0]
		assert info.port == config.port
		assert info.properties.get(b"version").decode("ascii") == __version__

		await asyncio.sleep(1)
		await unregister_opsi_services()
		await asyncio.sleep(1)
		assert len(services) == 0

		browser.cancel()
		await asyncio.sleep(1)
