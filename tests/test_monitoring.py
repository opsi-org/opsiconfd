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
import socket
import pytest
import urllib3
import requests

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

@pytest.mark.asyncio
async def test_check_product_status(config):

	data = json.dumps({'task': 'checkProductStatus', 'param': {'task': 'checkProductStatus', 'http': False, 'opsiHost': 'localhost', 'user': TEST_USER, 'productIds': ['firefox'], 'password': TEST_PW, 'port': 4447}}) # pylint: disable=line-too-long

	request = requests.post(f"{config.internal_url}/monitoring", auth=(TEST_USER, TEST_PW), data=data, verify=False) # pylint: disable=line-too-long
	assert request.status_code == 200
	assert request.json() == {'message': "OK: No Problem found for productIds: 'firefox'", 'state': 0}
