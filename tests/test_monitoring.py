# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import sys
import json
import os
from datetime import datetime, timedelta
import socket
import pytest
import urllib3
import requests

from MySQLdb import _mysql

TEST_USER = "adminuser"
TEST_PW = "adminuser"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)


@pytest.fixture(name="config")
def fixture_config(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel, redefined-outer-name
	return config


@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@pytest.fixture(autouse=True)
def create_data():

	mysql_host = os.environ.get("MYSQL_HOST")
	if not mysql_host:
		mysql_host = "127.0.0.1"
	db=_mysql.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi") # pylint: disable=invalid-name, c-extension-no-member
	now = datetime.now()

	for i in range(0,5):
		sql_string = f'INSERT INTO HOST (hostId, type, created, lastSeen) VALUES ("pytest-client-{i}.uib.local", "OpsiClient", "{now}", "{now}");'
		db.query(sql_string)
		sql_string = f'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) VALUES ("pytest-prod-{i}", "1.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT {i}", 60+{i});'  # pylint: disable=line-too-long
		db.query(sql_string)
		sql_string = f'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES ("pytest-prod-{i}", "1.0", "1", "{socket.getfqdn()}", "LocalbootProduct");' # pylint: disable=line-too-long
		db.query(sql_string)
	sql_string = f'INSERT INTO PRODUCT_ON_CLIENT (productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) \
	 	VALUES ("pytest-prod-1", "pytest-client-1.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}");'  # pylint: disable=line-too-long
	db.query(sql_string)

	sql_string = f'INSERT INTO PRODUCT_ON_CLIENT (productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) \
	 	VALUES ("pytest-prod-2", "pytest-client-2.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}");'  # pylint: disable=line-too-long
	db.query(sql_string)

	sql_string = f'INSERT INTO PRODUCT_ON_CLIENT (productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) \
	 	VALUES ("pytest-prod-3", "pytest-client-3.uib.local", "LocalbootProduct", "installed", "none", "none", "1.0", 1, "{now}");'  # pylint: disable=line-too-long
	db.query(sql_string)

	sql_string = f'INSERT INTO HOST (hostId, type, created, lastSeen) VALUES ("pytest-lost-client.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=31)}");'
	db.query(sql_string)

	db.store_result()


	yield

	db.query('DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "pytest%";')
	db.query('DELETE FROM PRODUCT_ON_CLIENT WHERE productId like "pytest%";')
	db.query('DELETE FROM HOST WHERE hostId like "pytest%";')
	db.query('DELETE FROM PRODUCT WHERE productId like "pytest%";')


	db.store_result()





def test_check_product_status_none(config):

	data = json.dumps({'task': 'checkProductStatus', 'param': {'task': 'checkProductStatus', 'http': False, 'opsiHost': 'localhost', 'user': TEST_USER, 'productIds': ['firefox'], 'password': TEST_PW, 'port': 4447}}) # pylint: disable=line-too-long

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == {'message': "OK: No Problem found for productIds: 'firefox'", 'state': 0}


test_data = [
	(["pytest-prod-1"], {'message': f"WARNING: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-1' action set on 1 clients!\n", 'state': 1}),
	(["pytest-prod-2"], {'message': f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-2' problems found on 1 clients!\n", 'state': 2}),
	(["pytest-prod-1","pytest-prod-2"], {'message': f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-1' action set on 1 clients!\nFor product 'pytest-prod-2' problems found on 1 clients!\n", 'state': 2}),
	(["pytest-prod-3"], {'message': "OK: No Problem found for productIds: 'pytest-prod-3'", 'state': 0}),
	(["pytest-prod-1","pytest-prod-2","pytest-prod-3"], {'message': f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-1' action set on 1 clients!\nFor product 'pytest-prod-2' problems found on 1 clients!\n", 'state': 2}),
]


@pytest.mark.parametrize("products, expected_result", test_data)
def test_check_product_status_action(config, create_data, products, expected_result):

	data = json.dumps({'task': 'checkProductStatus', 'param': {'task': 'checkProductStatus', 'http': False, 'opsiHost': 'localhost', 'user': TEST_USER, 'productIds': products, 'password': TEST_PW, 'port': 4447}}) # pylint: disable=line-too-long

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result


def test_check_client_status(config, create_data):

	data = json.dumps({'task': 'checkClientStatus', 'param': {'task': 'checkClientStatus', 'http': False, 'opsiHost': 'localhost', 'user': TEST_USER, 'clientId': 'pytest-lost-client.uib.local', 'password': TEST_PW, 'port': 4447}}) # pylint: disable=line-too-long

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	message = "WARNING: opsi-client pytest-lost-client.uib.local has not been seen, since 31 days. Please check opsi-client-agent installation on client or perhaps a client that can be deleted. "
	assert request.json() == {'message': f"{message}", 'state': 1}