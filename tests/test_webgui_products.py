# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd webgui products
"""

import os
import socket
from string import Template
import pytest
import json
import requests

from .utils import ( # pylint: disable=unused-import
	config, clean_redis, database_connection, create_check_data, disable_request_warning,
	ADMIN_USER, ADMIN_PASS
)

FQDN = socket.getfqdn()
FILE_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)),"data","webgui","products")

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
			'selectedClients': ["pytest-client-1.uib.local", "pytest-client-4.uib.local"],
			'selectedDepots': [FQDN],
			'type': 'LocalbootProduct',
			'pageNumber': 1,
			'perPage': 90,
			'sortBy': 'productId',
			'sortDesc': False,
			'filterQuery': ''
		},
		f"{FILE_DIR}/products-get1.json"
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
		f"{FILE_DIR}/products-get2.json"
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
		f"{FILE_DIR}/products-get3.json"
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
		f"{FILE_DIR}/products-get4.json"
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
		f"{FILE_DIR}/products-get5.json"
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
		f"{FILE_DIR}/products-get6.json"
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
		f"{FILE_DIR}/products-get7.json"
	)
]

@pytest.mark.parametrize("input_data, expected_result", test_data)
@pytest.mark.asyncio
async def test_products(config, input_data, expected_result): # pylint: disable=too-many-arguments,redefined-outer-name
	res = requests.get(
		f"{config.external_url}/webgui/api/opsidata/products", auth=(ADMIN_USER, ADMIN_PASS), verify=False, params=input_data
	)

	with open(expected_result, "r", encoding="utf-8") as f:
		json_string = Template(f.read()).substitute(FQDN=FQDN, depots=depots, depot_versions=list(depot_versions.values())).replace("'",'"')
		print(json_string)
		json_data = json.loads(json_string)

		print(json_data)

	assert res.status_code == 200
	assert res.json() == json_data
