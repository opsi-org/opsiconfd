# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""

import sys
import json
import os
from datetime import datetime
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

	db.store_result()


	yield

	db.query('DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "pytest%";')
	db.query('DELETE FROM PRODUCT_ON_CLIENT WHERE productId like "pytest%";')
	db.query('DELETE FROM HOST WHERE hostId like "pytest%";')
	db.query('DELETE FROM PRODUCT WHERE productId like "pytest%";')


	db.store_result()




@pytest.mark.asyncio
async def test_check_product_status_none(config):

	data = json.dumps({'task': 'checkProductStatus', 'param': {'task': 'checkProductStatus', 'http': False, 'opsiHost': 'localhost', 'user': TEST_USER, 'productIds': ['firefox'], 'password': TEST_PW, 'port': 4447}}) # pylint: disable=line-too-long

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == {'message': "OK: No Problem found for productIds: 'firefox'", 'state': 0}


test_data = [
	(["pytest-prod-1"], {'message': f"WARNING: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-1' action set on 1 clients!\n", 'state': 1}),
	(["pytest-prod-2"], {'message': f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-2' problems found on 1 clients!\n", 'state': 2}),
	(["pytest-prod-1","pytest-prod-2"], {'message': f"CRITICAL: \nResult for Depot: '{socket.getfqdn()}':\nFor product 'pytest-prod-1' action set on 1 clients!\nFor product 'pytest-prod-2' problems found on 1 clients!\n", 'state': 2}),
]

@pytest.mark.asyncio
@pytest.mark.parametrize("products, expected_result", test_data)
async def test_check_product_status_action(config, create_data, products, expected_result):

	data = json.dumps({'task': 'checkProductStatus', 'param': {'task': 'checkProductStatus', 'http': False, 'opsiHost': 'localhost', 'user': TEST_USER, 'productIds': products, 'password': TEST_PW, 'port': 4447}}) # pylint: disable=line-too-long

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == expected_result
