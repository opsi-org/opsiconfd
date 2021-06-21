# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0


import json
import socket
import pytest
import requests
from starlette.requests import Request
from starlette.datastructures import Headers
from opsiconfd.application.webgui.webgui import products
from opsiconfd.backend import get_backend
from .utils import clean_redis, config, create_check_data, disable_request_warning, TEST_USER, TEST_PW, HOSTNAME, LOCAL_IP, DAYS # pylint: disable=unused-import

TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)


FQDN = socket.getfqdn()
CONFD_URL = f"https://{FQDN}:4447"

test_data = [
	(
		{
			"selectedClients": ["pytest-client-1.uib.local", "pytest-client-4.uib.local"],
    		"selectedDepots": [FQDN],
			"type": "LocalbootProduct",
			"pageNumber": 1,
			"perPage": 90,
			"sortBy": "productId",
			"sortDesc": False,
			"filterQuery":""
		},
		{
			"result": {
				"products": [
					{
						"productId": "pytest-prod-0",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-1",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": [
							"pytest-client-1.uib.local"
						],
						"installationStatus": [
							"not_installed"
						],
						"actionRequest": [
							"setup"
						],
						"actionProgress": None,
						"actionResult": [
							"none"
						],
						"clientVersions": [
							"1.0-1"
						],
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-2",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-3",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-4",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": [
							"pytest-client-1.uib.local",
							"pytest-client-4.uib.local"
						],
						"installationStatus": [
							"not_installed",
							"not_installed"
						],
						"actionRequest": [
							"none",
							"setup"
						],
						"actionProgress": None,
						"actionResult": [
							"none",
							"none"
						],
						"clientVersions": [
							"1.0-1",
							"1.0-1"
						],
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					}
				],
				"total": 5
			},
			"configserver": FQDN
		}
	),
	(
		{
			"type": "LocalbootProduct",
			"pageNumber": 1,
			"perPage": 90,
			"sortBy": "productId",
			"sortDesc": False,
			"filterQuery":"",
		},
		{
			"result": {
				"products": [
					{
						"productId": "pytest-prod-0",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-1",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-2",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-3",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-4",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					}
				],
				"total": 5
			},
			"configserver": FQDN
		}
	),
	(
		{
			"selectedClients": ["pytest-client-1.uib.local", "pytest-client-4.uib.local"],
    		"selectedDepots": [FQDN, "test-depot.uib.gmbh"].sort(),
			"type": "LocalbootProduct",
			"pageNumber": 1,
			"perPage": 2,
			"sortBy": "productId",
			"sortDesc": False,
			"filterQuery":"",
		},
		{
			"result": {
				"products": [
					{
						"productId": "pytest-prod-0",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-1",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": [
							"pytest-client-1.uib.local"
						],
						"installationStatus": [
							"not_installed"
						],
						"actionRequest": [
							"setup"
						],
						"actionProgress": None,
						"actionResult": [
							"none"
						],
						"clientVersions": [
							"1.0-1"
						],
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					}
				],
				"total": 5
			},
			"configserver": FQDN
		}
	),
	(
		{
			"selectedClients": ["pytest-client-1.uib.local", "pytest-client-4.uib.local"],
    		"selectedDepots": [FQDN, "test-depot.uib.gmbh"].sort(),
			"type": "LocalbootProduct",
			"pageNumber": 2,
			"perPage": 2,
			"sortBy": "productId",
			"sortDesc": False,
			"filterQuery":"",
		},
		{
			"result": {
				"products": [
					{
						"productId": "pytest-prod-2",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-3",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					}
				],
				"total": 5
			},
			"configserver": FQDN
		}
	),
	(
		{
			"selectedClients": ["pytest-client-1.uib.local", "pytest-client-4.uib.local"],
			"selectedDepots": [FQDN, "pytest-test-depot.uib.gmbh","pytest-test-depot2.uib.gmbh"],
			"type": "LocalbootProduct",
			"pageNumber":1,
			"perPage":3,
			"sortBy":"productId",
			"sortDesc":False,
			"filterQuery":""
		},
		{
			"result": {
				"products": [
					{
						"productId": "pytest-prod-0",
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-1",
						"selectedDepots": [
							FQDN,
							"pytest-test-depot.uib.gmbh",
							"pytest-test-depot2.uib.gmbh"
						].sort(),
						"selectedClients": [
							"pytest-client-1.uib.local"
						],
						"installationStatus": [
							"not_installed"
						],
						"actionRequest": [
							"setup"
						],
						"actionProgress": None,
						"actionResult": [
							"none"
						],
						"clientVersions": [
							"1.0-1"
						],
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1",
							"1.0-1",
							"2.0-1"
						],
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-2",
						"selectedDepots": [
							FQDN,
							"pytest-test-depot.uib.gmbh",
							"pytest-test-depot2.uib.gmbh"
						].sort(),
						"selectedClients": None,
						"installationStatus": None,
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1",
							"1.0-1",
							"1.0-1"
						],
						"productType": "LocalbootProduct"
					}
				],
				"total": 5
			},
			"configserver": FQDN
		}
	),
	(
		{
			"selectedClients": ["pytest-client-1.uib.local", "pytest-client-4.uib.local"],
			"selectedDepots": [FQDN, "pytest-test-depot.uib.gmbh","pytest-test-depot2.uib.gmbh"],
			"type": "LocalbootProduct",
			"pageNumber":1,
			"perPage":3,
			"sortBy":"productId",
			"sortDesc":False,
			"filterQuery":"prod-1"
		},
		{
			"result": {
				"products": [
					{
						"productId": "pytest-prod-1",
						"selectedDepots": [
							"marvin-t590.uib.local",
							"pytest-test-depot.uib.gmbh",
							"pytest-test-depot2.uib.gmbh"
						].sort(),
						"selectedClients": [
							"pytest-client-1.uib.local"
						],
						"installationStatus": [
							"not_installed"
						],
						"actionRequest": [
							"setup"
						],
						"actionProgress": None,
						"actionResult": [
							"none"
						],
						"clientVersions": [
							"1.0-1"
						],
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1",
							"1.0-1",
							"2.0-1"
						],
						"productType": "LocalbootProduct"
					}
				],
				"total": 1
			},
			"configserver": "marvin-t590.uib.local"
		}
	),
	(
		{
			"selectedClients": ["pytest-client-1.uib.local", "pytest-client-4.uib.local"],
			"selectedDepots": [FQDN, "pytest-test-depot.uib.gmbh","pytest-test-depot2.uib.gmbh"],
			"type": "LocalbootProduct",
			"pageNumber":1,
			"perPage":3,
			"sortBy":"productId",
			"sortDesc":False,
			"filterQuery":"ffff"
		},
		{
			"result": {
				"products": [],
				"total": 0
			},
			"configserver": "marvin-t590.uib.local"
		}
	)
]

@pytest.mark.parametrize("input_data, expected_result", test_data)
@pytest.mark.asyncio
async def test_products(input_data, expected_result, create_check_data): # pylint: disable=too-many-arguments

	data = json.dumps(input_data)

	res = requests.post(f"{CONFD_URL}/webgui/api/opsidata/products", auth=(TEST_USER, TEST_PW), verify=False, data=data)
	print(res.json())
	print(expected_result)
	assert res.status_code == 200
	assert res.json() == expected_result
