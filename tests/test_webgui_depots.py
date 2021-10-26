# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd webgui products
"""

import socket
import pytest
from string import Template
import requests
import json
import os
from datetime import datetime
from fastapi import status



from .utils import ( # pylint: disable=unused-import
	config, clean_redis, database_connection, create_check_data, disable_request_warning,
	ADMIN_USER, ADMIN_PASS
)

API_ROOT = "/addons/webgui/api/opsidata"
FQDN = socket.getfqdn()
FILE_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)),"data","webgui","depots")



test_data = [
	(
		"depots",
		{"filterQuery": "depot2", "perPage": 1, "pageNumber": 1, "sortBy": "[depotId,ip]", "sortDesc": False},
		f"{FILE_DIR}/depots-get1.json"
	),
	(
		"depot_ids",
		{},
		f"{FILE_DIR}/depot-ids-get1.json"
	),
	(
		"depots/clients",
		{},
		f"{FILE_DIR}/depots-clients-get1.json"
	)
	,
	(
		"depots/clients",
		{"selectedDepots": "pytest-test-depot2.uib.gmbh"},
		f"{FILE_DIR}/depots-clients-get2.json"
	)
]

@pytest.mark.parametrize("path, query_params, expected_result", test_data)
@pytest.mark.asyncio
async def test_depots_get(config, path, query_params, expected_result): # pylint: disable=too-many-arguments,redefined-outer-name
	print(query_params)
	res = requests.get(
		f"{config.external_url}{API_ROOT}/{path}", auth=(ADMIN_USER, ADMIN_PASS), verify=False, params=query_params,
	)

	with open(expected_result, "r", encoding="utf-8") as f:
		json_data = json.loads(Template(f.read()).substitute(FQDN=FQDN).replace("'",'"'))


	assert res.status_code == status.HTTP_200_OK
	if isinstance(json_data, list) and isinstance(json_data[0], dict):
		assert sorted(res.json(), key=lambda item: item["depotId"]) == sorted(json_data, key=lambda item: item["depotId"])
	else:
		assert sorted(res.json()) == sorted(json_data)



