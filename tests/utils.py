# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import os
import asyncio
import pytest
import socket
import json
from datetime import datetime, timedelta
import aredis
import urllib3
import requests
import sys

import MySQLdb

TEST_USER = "adminuser"
TEST_PW = "adminuser"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)
OPSI_SESSION_KEY = "opsiconfd:sessions"
DAYS = 31

@pytest.fixture(name="config")
def config(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel, redefined-outer-name
	return config

@pytest.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis(config): # pylint: disable=redefined-outer-name
	yield None
	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)
	session_keys = redis_client.scan_iter(f"{OPSI_SESSION_KEY}:*")
	async for key in session_keys:
		await redis_client.delete(key)
	await redis_client.delete(f"opsiconfd:stats:client:failed_auth:{LOCAL_IP}")
	await redis_client.delete(f"opsiconfd:stats:client:blocked:{LOCAL_IP}")
	client_keys = redis_client.scan_iter("opsiconfd:stats:client*")
	async for key in client_keys:
		await redis_client.delete(key)
	await redis_client.delete("opsiconfd:stats:rpcs")
	await redis_client.delete("opsiconfd:stats:num_rpcs")
	rpc_keys = redis_client.scan_iter("opsiconfd:stats:rpc:*")
	async for key in rpc_keys:
		await redis_client.delete(key)
	await asyncio.sleep(5)



def create_depot(opsi_url, depot_name):
	params= [depot_name,None,"file:///var/lib/opsi/depot","smb://172.17.0.101/opsi_depot",None,"file:///var/lib/opsi/repository","webdavs://172.17.0.101:4447/repository"] # pylint: disable=line-too-long

	rpc_request_data = json.dumps({"id": 1, "method": "host_createOpsiDepotserver", "params": params})
	res = requests.post(f"{opsi_url}/rpc", auth=(TEST_USER, TEST_PW), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)
	print(result_json)



@pytest.fixture(autouse=True)
def create_check_data(config):

	mysql_host = os.environ.get("MYSQL_HOST")
	if not mysql_host:
		mysql_host = "127.0.0.1"

	db=MySQLdb.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi") # pylint: disable=invalid-name, c-extension-no-member
	now = datetime.now()

	db.autocommit(True)
	cursor = db.cursor()

	cursor.execute(
		(
			'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "pytest%";'
			'DELETE FROM PRODUCT_ON_CLIENT WHERE productId like "pytest%";'
			'DELETE FROM PRODUCT WHERE productId like "pytest%";'
			'DELETE FROM HOST WHERE hostId like "pytest%";'
		)
	)

	# Product
	for i in range(0,5):
		sql_string = (f'INSERT INTO HOST (hostId, type, created, lastSeen) VALUES ("pytest-client-{i}.uib.local", '
			f'"OpsiClient", "{now}", "{now}");')
		cursor.execute(sql_string)
		sql_string = ('INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) '
			f'VALUES ("pytest-prod-{i}", "1.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT {i}", 60+{i});')  # pylint: disable=line-too-long
		cursor.execute(sql_string)
		sql_string = f'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES ("pytest-prod-{i}", "1.0", "1", "{socket.getfqdn()}", "LocalbootProduct");' # pylint: disable=line-too-long
		cursor.execute(sql_string)

	cursor.execute(
		(
			'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) '
			'VALUES ("pytest-prod-1", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 1 version 2", 60);'
		)
	)

	# Host
	cursor.execute(
		(
			'INSERT INTO HOST (hostId, type, created, lastSeen)'
			f'VALUES ("pytest-lost-client.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=DAYS)}");'
			'INSERT INTO HOST (hostId, type, created, lastSeen) '
			f'VALUES ("pytest-lost-client-fp.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=DAYS)}");'
			'INSERT INTO HOST (hostId, type, created, lastSeen) '
			f'VALUES ("pytest-lost-client-fp2.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=DAYS)}");'
		)
	)

	create_depot(config.internal_url, "pytest-test-depot.uib.gmbh")
	create_depot(config.internal_url, "pytest-test-depot2.uib.gmbh")

	# Product on client
	cursor.execute(
		(
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
			f'VALUES ("pytest-prod-1", "pytest-client-1.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}");'
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
	 		f'VALUES ("pytest-prod-2", "pytest-client-2.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}");'
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
	 		f'VALUES ("pytest-prod-3", "pytest-client-3.uib.local", "LocalbootProduct", "installed", "none", "none", "1.0", 1, "{now}");'
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
			f'VALUES ("pytest-prod-2", "pytest-lost-client-fp.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}");'
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
			f'VALUES ("pytest-prod-2", "pytest-lost-client-fp2.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}");'
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
			f'VALUES ("pytest-prod-1", "pytest-lost-client-fp2.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}");'
		)
	)

	# Product on depot
	cursor.execute((
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) '
			'VALUES ("pytest-prod-1", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct");'
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) '
			'VALUES ("pytest-prod-2", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct");'
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) '
			'VALUES ("pytest-prod-1", "2.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct"); '
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) '
			'VALUES ("pytest-prod-2", "1.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct");'
		)
	)
	cursor.close()

	yield

	cursor = db.cursor()
	cursor.execute(
		(
			'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "pytest%";'
			'DELETE FROM PRODUCT_ON_CLIENT WHERE productId like "pytest%";'
			'DELETE FROM PRODUCT WHERE productId like "pytest%";'
			'DELETE FROM HOST WHERE hostId like "pytest%";'
		)
	)
	cursor.close()

@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
