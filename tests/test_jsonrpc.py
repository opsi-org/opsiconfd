# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
jsonrpc tests
"""

import json
import requests
import pytest

from .utils import (  # pylint: disable=unused-import
	config, clean_redis, database_connection, ADMIN_USER, ADMIN_PASS
)


@pytest.fixture(name="fill_db")
def fixture_fill_db(database_connection):  # pylint: disable=unused-argument,redefined-outer-name
	mysql_data = [
		{
			"hostId": "pytest.uib.gmbh",
			"type": "OpsiClient",
			"description": "pytest test data description",
			"notes": "pytest test data notes",
			"hardwareAddress": "32:58:fd:f7:3b:26",
			"ipAddress": "192.168.0.12",
			"inventoryNumber": "0815",
			"created": "2017-11-14 14:43:48",
			"lastSeen": "2017-11-14 14:43:48"

		},
		{
			"hostId": "pytest2.uib.gmbh",
			"type": "OpsiClient",
			"description": "pytest test data description",
			"notes": "pytest test data notes",
			"hardwareAddress": "32:58:fd:f7:3b:26",
			"ipAddress": "192.168.0.111",
			"inventoryNumber": "0815",
			"created": "2017-11-14 14:43:48",
			"lastSeen": "2017-11-14 14:43:48"

		},
		{
			"hostId": "pytest3.uib.gmbh",
			"type": "OpsiClient",
			"description": "pytest test data description",
			"notes": "pytest test data notes",
			"hardwareAddress": "32:58:fd:f7:3b:26",
			"ipAddress": "192.168.0.111",
			"inventoryNumber": "0815",
			"created": "2017-11-14 14:43:48",
			"lastSeen": "2017-11-14 14:43:48"

		},
		{
			"hostId": "pytest4.uib.gmbh",
			"type": "OpsiClient",
			"description": "pytest test data description",
			"notes": "pytest test data notes",
			"hardwareAddress": "32:58:fd:f7:3b:26",
			"ipAddress": "192.168.0.111",
			"inventoryNumber": "0815",
			"created": "2017-11-14 14:43:48",
			"lastSeen": "2017-11-14 14:43:48"

		}
	]

	# TODO assert mysql results
	# TODO insert more Data
	for data in mysql_data:
		sql_string = f'INSERT INTO HOST (hostId, type, description, notes,  hardwareAddress, ipAddress, inventoryNumber, created, lastSeen) VALUES (\"{data["hostId"]}\", \"{data["type"]}\", \"{data["description"]}\", \"{data["notes"]}\", \"{data["hardwareAddress"]}\", \"{data["ipAddress"]}\", \"{data["inventoryNumber"]}\", \"{data["created"]}\",  \"{data["lastSeen"]}\");'  # pylint: disable=line-too-long
		database_connection.query(sql_string)
		database_connection.query(f'SELECT * FROM HOST WHERE ipAddress like \"{data["ipAddress"]}\";')
		database_connection.store_result()
	database_connection.commit()

	yield None

	for data in mysql_data:
		database_connection.query(f'DELETE FROM HOST WHERE ipAddress like \"{data["ipAddress"]}\";')
	database_connection.commit()


jsonrpc_test_data = [
	(
		{"id": 1, "method": "host_getObjects", "params": [["ipAddress", "id", "notes"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": "192.168.0.12",
			"notes": "pytest test data notes",
			"type": "OpsiClient",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [["ipAddress"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": "192.168.0.12",
			"notes": None,
			"type": "OpsiClient",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [["id"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": None,
			"notes": None,
			"type": "OpsiClient",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [[], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 1,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": "192.168.0.12",
			"notes": "pytest test data notes",
			"type": "OpsiClient",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [["bla"], {"ipAddress": "192.168.0.12"}]},
		{
			"num_results": 0,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest.uib.gmbh",
			"ipAddress": "192.168.0.12",
			"notes": "pytest test data notes",
			"type": "OpsiClient",
			"error": {
				"message": "Invalid attribute 'bla'",
				"class": "ValueError",
			}
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [[], {"notes": "no results for this request"}]},
		{
			"num_results": 0,
			"status_code": 200,
			"method": "host_getObjects",
			"error": None
		}
	),
	(
		{"id": 1, "method": "host_getObjects", "params": [["ipAddress"], {"ipAddress": "192.168.0.111"}]},
		{
			"num_results": 3,
			"status_code": 200,
			"method": "host_getObjects",
			"id": "pytest2.uib.gmbh",
			"ipAddress": "192.168.0.111",
			"notes": None,
			"type": "OpsiClient",
			"error": None
		}
	)

]


@pytest.mark.parametrize("request_data, expected_result", jsonrpc_test_data)
def test_process_jsonrpc_request(config, fill_db, request_data, expected_result):  # pylint: disable=unused-argument,redefined-outer-name
	rpc_request_data = json.dumps(request_data)
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	assert res.status_code == expected_result.get("status_code")

	if result_json.get("error") is None:
		assert len(result_json.get("result")) == expected_result.get("num_results")
		if len(result_json.get("result")) > 0:
			assert result_json.get("result")[0].get("notes") == expected_result.get("notes")
			assert result_json.get("result")[0].get("ipAddress") == expected_result.get("ipAddress")
			assert result_json.get("result")[0].get("id") == expected_result.get("id")
			assert result_json.get("result")[0].get("type") == expected_result.get("type")
	else:
		error = result_json.get("error")
		expected_error = expected_result.get("error")
		assert error.get("message") == expected_error.get("message")
		assert error.get("class") == expected_error.get("class")


def test_create_opsi_Client(config, database_connection):  # pylint: disable=invalid-name,redefined-outer-name
	request_data = {
		"id": 1,
		"method": "host_createOpsiClient",
		"params": [
			"test.fabian.uib.local"
		]
	}

	rpc_request_data = json.dumps(request_data)

	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	assert result_json.get("error") is None
	assert res.status_code == 200

	request_data = {
		"id": 1,
		"method": "host_getObjects",
		"params": [
			[],
			{
				"id": "test.fabian.uib.local"
			}
		]
	}

	rpc_request_data = json.dumps(request_data)
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	assert len(result_json.get("result")) == 1
	assert result_json.get("result")[0].get("id") == "test.fabian.uib.local"
	assert result_json.get("error") is None
	database_connection.query('DELETE FROM HOST WHERE hostId like "test.fabian.uib.local"')
	database_connection.commit()

	rpc_request_data = json.dumps(request_data)
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	assert len(result_json.get("result")) == 0
	assert result_json.get("error") is None


def test_delete_opsi_client(config, fill_db):  # pylint: disable=unused-argument,invalid-name,redefined-outer-name

	request_data = {
		"id": 1,
		"method": "host_getObjects",
		"params": [
			[],
			{
				"id": "pytest4.uib.gmbh"
			}
		]
	}

	rpc_request_data = json.dumps(request_data)
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	assert len(result_json.get("result")) == 1
	assert result_json.get("result")[0].get("id") == "pytest4.uib.gmbh"
	assert result_json.get("error") is None

	delete_request = {
		"id": 1,
		"method": "host_delete",
		"params": ["pytest4.uib.gmbh"]
	}
	rpc_delete_request = json.dumps(delete_request)
	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_delete_request, verify=False)
	assert res.status_code == 200
	result_json = json.loads(res.text)

	assert result_json.get("error") is None
	assert result_json.get("result") is None

	res = requests.post(f"{config.internal_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)

	assert len(result_json.get("result")) == 0
	assert result_json.get("error") is None
