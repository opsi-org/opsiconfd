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
import requests
import json
import os
from datetime import datetime
from fastapi import status
from starlette.status import HTTP_200_OK, HTTP_409_CONFLICT


from .utils import ( # pylint: disable=unused-import
	config, clean_redis, database_connection, create_check_data, disable_request_warning,
	ADMIN_USER, ADMIN_PASS
)

API_ROOT = "/addons/webgui/api/opsidata"
FQDN = socket.getfqdn()
FILE_DIR = os.path.abspath(os.path.dirname(__file__))

test_data = [
	(
		{},
		f"{FILE_DIR}/data/webgui/clients/clients-get1.json"
	),
	(
		{"perPage": 2, "pageNumber": 2},
		f"{FILE_DIR}/data/webgui/clients/clients-get2.json"
	),
	(
		{"filterQuery": "lost-client", "perPage": 2, "pageNumber": 2, "sortDesc": False, "sortBy": "clientId"},
		f"{FILE_DIR}/data/webgui/clients/clients-get3.json"
	),
	(
		{"sortBy": "clientId"},
		f"{FILE_DIR}/data/webgui/clients/clients-get4.json"
	),
	(
		{"sortBy": "[installationStatus_installed,actionResult_failed]"},
		f"{FILE_DIR}/data/webgui/clients/clients-get5.json"
	)
]

@pytest.mark.parametrize("query_params, expected_result", test_data)
@pytest.mark.asyncio
async def test_clients_get(config, query_params, expected_result): # pylint: disable=too-many-arguments,redefined-outer-name
	res = requests.get(
		f"{config.external_url}{API_ROOT}/clients", auth=(ADMIN_USER, ADMIN_PASS), verify=False, params=query_params,
	)

	with open(expected_result, "r", encoding="utf-8") as f:
		json_data = json.loads(f.read())

	assert res.status_code == 200
	assert res.json() == json_data

test_data = [
	(
		{},
		f"{FILE_DIR}/data/webgui/clients/clients-create1.json",
		status.HTTP_422_UNPROCESSABLE_ENTITY
	),
	(
		{
			"hostId": "myclient.test.local",
			"inventoryNumber": 120,
			"description": "test client"
		},
		f"{FILE_DIR}/data/webgui/clients/clients-create2.json",
		status.HTTP_201_CREATED
	)
]




@pytest.mark.parametrize("data, expected_result, http_status", test_data)
@pytest.mark.asyncio
async def test_clients_create(config, data, expected_result, http_status): # pylint: disable=too-many-arguments,redefined-outer-name
	res = requests.post(
		f"{config.external_url}{API_ROOT}/clients", auth=(ADMIN_USER, ADMIN_PASS), verify=False, data=json.dumps(data),
	)

	if expected_result:
		with open(expected_result, "r", encoding="utf-8") as f:
			json_data = json.loads(f.read())
			res_body = res.json()
			if http_status == 201:
				res_body["created"] = res_body["created"][:-3]
				res_body["lastSeen"] = res_body["lastSeen"][:-3]
				json_data["created"] = datetime.now().strftime("%Y-%m-%d %H:%M")
				json_data["lastSeen"] = json_data["created"]


	assert res.status_code == http_status
	assert res_body == json_data

	if http_status == 201:
		res = requests.get(
			f"{config.external_url}{API_ROOT}/clients/{data['hostId']}", auth=(ADMIN_USER, ADMIN_PASS), verify=False, data=data,
		)

		assert res.status_code == status.HTTP_200_OK
		assert res_body == json_data


@pytest.mark.asyncio
async def test_clients_create_integrity_error(config): # pylint: disable=too-many-arguments,redefined-outer-name

	data = {
			"hostId": "myclient.test.local",
			"inventoryNumber": 120,
			"description": "test client"
	}
	res = requests.post(
		f"{config.external_url}{API_ROOT}/clients", auth=(ADMIN_USER, ADMIN_PASS), verify=False, data=json.dumps(data),
	)
	res_body = res.json()
	with open(f"{FILE_DIR}/data/webgui/clients/clients-create2.json", "r", encoding="utf-8") as f:
		json_data = json.loads(f.read())
		res_body["created"] = res_body["created"][:-3]
		res_body["lastSeen"] = res_body["lastSeen"][:-3]
		json_data["created"] = datetime.now().strftime("%Y-%m-%d %H:%M")
		json_data["lastSeen"] = json_data["created"]

	assert res.status_code == status.HTTP_201_CREATED
	assert res_body == json_data

	res = requests.get(
		f"{config.external_url}{API_ROOT}/clients/{data['hostId']}", auth=(ADMIN_USER, ADMIN_PASS), verify=False, data=data,
	)
	res_body = res.json()
	res_body["created"] = res_body["created"][:-3]
	res_body["lastSeen"] = res_body["lastSeen"][:-3]
	assert res.status_code == status.HTTP_200_OK
	assert res_body == json_data

	# second create should give IntegrityError
	res = requests.post(
		f"{config.external_url}{API_ROOT}/clients", auth=(ADMIN_USER, ADMIN_PASS), verify=False, data=json.dumps(data),
	)
	res_body = res.json()
	assert res.status_code == status.HTTP_409_CONFLICT
	assert res_body.get("class") == "IntegrityError"
	assert res_body.get("message") == "Could not create client object. Client 'myclient.test.local'' already exists"


test_data = [
	(
		"pytest-client-1.uib.local",
		f"{FILE_DIR}/data/webgui/clients/clients-get6.json",
		status.HTTP_200_OK
	),
	(
		"no-client.uib.local",
		f"{FILE_DIR}/data/webgui/clients/clients-get7.json",
		status.HTTP_404_NOT_FOUND
	)

]

@pytest.mark.parametrize("client_id, expected_result, http_status", test_data)
@pytest.mark.asyncio
async def test_client_get(config, client_id, expected_result, http_status): # pylint: disable=too-many-arguments,redefined-outer-name
	res = requests.get(
		f"{config.external_url}{API_ROOT}/clients/{client_id}", auth=(ADMIN_USER, ADMIN_PASS), verify=False,
	)


	with open(expected_result, "r", encoding="utf-8") as f:
		json_data = json.loads(f.read())
		print(json_data.get("created"))

	res_data = res.json()
	if json_data.get("created"):
		del json_data["created"]
		del json_data["lastSeen"]
		del res_data["created"]
		del res_data["lastSeen"]

	assert res.status_code == http_status
	assert res_data == json_data


test_data = [
	(
		"pytest-client-1.uib.local",
		None,
		status.HTTP_200_OK
	),
	(
		"no-client.uib.local",
		{
			"class": "OpsiApiException",
			"code": None,
			"details": "None",
			"message": "Client with id 'no-client.uib.local' not found.",
			"status": 404
		},
		status.HTTP_404_NOT_FOUND
	)

]

@pytest.mark.parametrize("client_id, expected_result, http_status", test_data)
@pytest.mark.asyncio
async def test_clients_delete(config, client_id, expected_result, http_status): # pylint: disable=too-many-arguments,redefined-outer-name
	res = requests.delete(
		f"{config.external_url}{API_ROOT}/clients/{client_id}", auth=(ADMIN_USER, ADMIN_PASS), verify=False,
	)


	assert res.status_code == http_status
	assert res.json() == expected_result
