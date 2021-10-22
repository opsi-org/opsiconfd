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
from fastapi import status



from .utils import ( # pylint: disable=unused-import
	config, clean_redis, database_connection, create_check_data, disable_request_warning,
	ADMIN_USER, ADMIN_PASS
)

FQDN = socket.getfqdn()
FILE_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)),"data","webgui","hosts")


test_data = [
	(
		"hosts",
		{},
		f"{FILE_DIR}/hosts-get1.json"
	),
	(
		"hosts",
		{"sortBy": "type,hostId","perPage":2, "pageNumber": 6, "sortDesc": True},
		f"{FILE_DIR}/hosts-get2.json"
	),
	(
		"hosts",
		{"sortBy": "type,hostId","perPage":2, "pageNumber": 1, "sortDesc": True},
		f"{FILE_DIR}/hosts-get3.json"
	),
	(
		"hosts",
		{"sortBy": "type,hostId","perPage":2, "pageNumber": 1, "sortDesc": False},
		f"{FILE_DIR}/hosts-get4.json"
	)
]

@pytest.mark.parametrize("path, query_params, expected_result", test_data)
@pytest.mark.asyncio
async def test_hosts_get(config, path, query_params, expected_result): # pylint: disable=too-many-arguments,redefined-outer-name
	print(query_params)
	res = requests.get(
		f"{config.external_url}/webgui/api/opsidata/{path}", auth=(ADMIN_USER, ADMIN_PASS), verify=False, params=query_params,
	)
	res_data = res.json()
	with open(expected_result, "r", encoding="utf-8") as f:
		json_data = json.loads(Template(f.read()).substitute(FQDN=FQDN).replace("'",'"'))

	if json_data[0]:
		for data in json_data:
			del data["created"]
			del data["lastSeen"]
			del data["opsiHostKey"]
		for data in res_data:
			del data["created"]
			del data["lastSeen"]
			del data["opsiHostKey"]

	assert res.status_code == status.HTTP_200_OK
	assert sorted(res_data, key=lambda item: item["hostId"]) == sorted(json_data, key=lambda item: item["hostId"])



