# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd webgui products
"""

import json
import socket
import pytest
import requests
from starlette.requests import Request
from starlette.datastructures import Headers

from opsiconfd.backend import get_backend
from .utils import clean_redis, config, create_check_data, disable_request_warning, TEST_USER, TEST_PW, HOSTNAME, LOCAL_IP, DAYS # pylint: disable=unused-import

TEST_USER = "adminuser"
TEST_PW = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)


FQDN = socket.getfqdn()
CONFD_URL = f"https://{FQDN}:4447"


depots = sorted([
	FQDN,
	"pytest-test-depot.uib.gmbh",
	"pytest-test-depot2.uib.gmbh"
])
depot_versions = {
	FQDN: "1.0-1",
	"pytest-test-depot.uib.gmbh": "1.0-1",
	"pytest-test-depot2.uib.gmbh": "2.0-1"
}

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
						'name': 'Pytest dummy PRODUCT 0', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-1",
						'name': 'Pytest dummy PRODUCT 1', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": [
							"pytest-client-1.uib.local"
						],
						"installationStatusDetails": [
							"not_installed"
						],
						"installationStatus": "not_installed",
						"actionRequestDetails": [
							"setup"
						],
						"actionRequest": "setup",
						"actionProgress": None,
						"actionResultDetails": [
							"none"
						],
						"actionResult": "none",
						"clientVersions": [
							"1.0-1"
						],
						"client_version_outdated": False,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-2",
						'name': 'Pytest dummy PRODUCT 2', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-3",
						'name': 'Pytest dummy PRODUCT 3', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-4",
						'name': 'Pytest dummy PRODUCT 4', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": [
							"pytest-client-1.uib.local",
							"pytest-client-4.uib.local"
						],
						"installationStatusDetails": [
							"not_installed",
							"not_installed"
						],
						"installationStatus": "not_installed",
						"actionRequestDetails": [
							"none",
							"setup"
						],
						"actionRequest": "mixed",
						"actionProgress": None,
						"actionResultDetails": [
							"none",
							"none"
						],
						"actionResult": "none",
						"clientVersions": [
							"1.0-1",
							"1.0-1"
						],
						"client_version_outdated": True,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"depot_version_diff": False,
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
						'name': 'Pytest dummy PRODUCT 0', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-1",
						'name': 'Pytest dummy PRODUCT 1', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-2",
						'name': 'Pytest dummy PRODUCT 2', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-3",
						'name': 'Pytest dummy PRODUCT 3', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-4",
						'name': 'Pytest dummy PRODUCT 4', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
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
    		"selectedDepots": sorted([FQDN, "test-depot.uib.gmbh"]),
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
						'name': 'Pytest dummy PRODUCT 0', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-1",
						'name': 'Pytest dummy PRODUCT 1', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": [
							"pytest-client-1.uib.local"
						],
						"installationStatusDetails": [
							"not_installed"
						],
						"installationStatus": "not_installed",
						"actionRequestDetails": [
							"setup"
						],
						"actionRequest": "setup",
						"actionProgress": None,
						"actionResultDetails": [
							"none"
						],
						"actionResult": "none",
						"clientVersions": [
							"1.0-1"
						],
						"client_version_outdated": False,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1"
						],
						"depot_version_diff": False,
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
    		"selectedDepots": sorted([FQDN, "test-depot.uib.gmbh"]),
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
						'name': 'Pytest dummy PRODUCT 2', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
						"productType": "LocalbootProduct"
					},
					{
						"productId": "pytest-prod-3",
						'name': 'Pytest dummy PRODUCT 3', 'description': None,
						"selectedDepots": [
							FQDN
						],
						"selectedClients": None,
						"installationStatus": "not_installed",
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
						"depot_version_diff": False,
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
			"selectedDepots": ["pytest-test-depot.uib.gmbh", "pytest-test-depot2.uib.gmbh"],
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
						"productId": "pytest-prod-1",
						"name": "Pytest dummy PRODUCT 1",
						"description": None,
						"selectedDepots": [
							"pytest-test-depot.uib.gmbh",
							"pytest-test-depot2.uib.gmbh"
						],
						"selectedClients": [
							"pytest-client-1.uib.local"
						],
						"installationStatusDetails": [
							"not_installed"
						],
						"actionRequestDetails": [
							"setup"
						],
						"actionResultDetails": [
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
							"2.0-1"
						],
						"productType": "LocalbootProduct",
						"depot_version_diff": True,
						"installationStatus": "not_installed",
						"actionRequest": "setup",
						"actionProgress": None,
						"actionResult": "none",
						"client_version_outdated": False
					},
					{
						"productId": "pytest-prod-2",
						"name": "Pytest dummy PRODUCT 2",
						"description": None,
						"selectedDepots": [
							"pytest-test-depot.uib.gmbh",
							"pytest-test-depot2.uib.gmbh"
						],
						"selectedClients": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1",
							"1.0-1"
						],
						"productType": "LocalbootProduct",
						"depot_version_diff": False,
						"installationStatus": "not_installed",
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None
					},
					{
						"productId": "pytest-prod-3",
						"name": "Pytest dummy PRODUCT 3",
						"description": None,
						"selectedDepots": [
							"pytest-test-depot.uib.gmbh",
							"pytest-test-depot2.uib.gmbh"
						],
						"selectedClients": None,
						"clientVersions": None,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							"1.0-1",
							"1.0-1"
						],
						"productType": "LocalbootProduct",
						"depot_version_diff": False,
						"installationStatus": "not_installed",
						"actionRequest": None,
						"actionProgress": None,
						"actionResult": None
					}
				],
				"total": 4
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
						'name': 'Pytest dummy PRODUCT 1', 'description': None,
						"selectedDepots": depots,
						"selectedClients": [
							"pytest-client-1.uib.local"
						],
						"installationStatusDetails": [
							"not_installed"
						],
						"installationStatus": "not_installed",
						"actionRequestDetails": [
							"setup"
						],
						"actionRequest": "setup",
						"actionProgress": None,
						"actionResultDetails": [
							"none"
						],
						"actionResult": "none",
						"clientVersions": [
							"1.0-1"
						],
						"client_version_outdated": False,
						"actions": [
							"setup",
							"uninstall"
						],
						"depotVersions": [
							depot_versions.get(depots[0]),
							depot_versions.get(depots[1]),
							depot_versions.get(depots[2])
						],
						"depot_version_diff": True,
						"productType": "LocalbootProduct"
					}
				],
				"total": 1
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
			"filterQuery":"ffff"
		},
		{
			"result": {
				"products": [],
				"total": 0
			},
			"configserver": FQDN
		}
	)
]

@pytest.mark.parametrize("input_data, expected_result", test_data)
@pytest.mark.asyncio
async def test_products(input_data, expected_result, create_check_data): # pylint: disable=too-many-arguments

	data = json.dumps(input_data)

	res = requests.get(f"{CONFD_URL}/webgui/api/opsidata/products", auth=(TEST_USER, TEST_PW), verify=False, data=data)
	print(res.json())
	print(expected_result)

	assert res.status_code == 200
	assert res.json() == expected_result
