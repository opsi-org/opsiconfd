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

ADMIN_USER = "adminuser"
ADMIN_PASS = "adminuser"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)
BASE_URL = "https://localhost:4447"
OPSI_SESSION_KEY = "opsiconfd:sessions"
DAYS = 31

@pytest.fixture(name="config")
def config(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel, redefined-outer-name
	return config


@pytest.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis(config):  # pylint: disable=redefined-outer-name
	redis_client = aredis.StrictRedis.from_url(config.redis_internal_url)

	for redis_key in (
		OPSI_SESSION_KEY,
		"opsiconfd:stats:client:failed_auth",
		"opsiconfd:stats:client:blocked",
		"opsiconfd:stats:client",
		"opsiconfd:stats:rpcs",
		"opsiconfd:stats:num_rpcs",
		"opsiconfd:stats:rpc"
	):
		async for key in redis_client.scan_iter(f"{redis_key}:*"):
			await redis_client.delete(key)
	yield None


def create_depot_rpc(opsi_url: str, host_id: str, host_key: str = None):
	params= [
		host_id,
		host_key,
		"file:///var/lib/opsi/depot",
		"smb://172.17.0.101/opsi_depot",
		None,
		"file:///var/lib/opsi/repository",
		"webdavs://172.17.0.101:4447/repository"
	]
	rpc_request_data = json.dumps({"id": 1, "method": "host_createOpsiDepotserver", "params": params})
	res = requests.post(f"{opsi_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), data=rpc_request_data, verify=False)
	result_json = json.loads(res.text)
	return result_json



@pytest.fixture(autouse=True)
def create_check_data(config):
	print("create_check_data")

	mysql_host = os.environ.get("MYSQL_HOST")
	if not mysql_host:
		mysql_host = "127.0.0.1"

	db=MySQLdb.connect(host=mysql_host,user="opsi",passwd="opsi",db="opsi") # pylint: disable=invalid-name, c-extension-no-member
	now = datetime.now()

	db.autocommit(True)
	cursor = db.cursor()

	# cursor.execute(
	# 	(
	# 		'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "pytest%";'
	# 		'DELETE FROM PRODUCT_ON_CLIENT WHERE productId like "pytest%";'
	# 		'DELETE FROM OBJECT_TO_GROUP WHERE groupId like "pytest%";'
	# 		'DELETE FROM PRODUCT WHERE productId like "pytest%";'
	# 		'DELETE FROM HOST WHERE hostId like "pytest%";'
	# 		'DELETE FROM opsi.GROUP WHERE groupId like "pytest%";'
	# 	)
	# )

	cursor.execute(
		(
			'DELETE FROM PRODUCT_ON_DEPOT;'
			'DELETE FROM PRODUCT_ON_CLIENT;'
			'DELETE FROM PRODUCT_PROPERTY_VALUE;'
			'DELETE FROM PRODUCT_PROPERTY;'
			'DELETE FROM PRODUCT_DEPENDENCY;'
			'DELETE FROM OBJECT_TO_GROUP;'
			'DELETE FROM PRODUCT;'
			'DELETE FROM HOST WHERE type!="OpsiConfigserver";'
			'DELETE FROM opsi.GROUP;'
			'DELETE FROM CONFIG_STATE WHERE objectId like "pytest%";'
		)
	)

	# Product
	for i in range(0,5):
		sql_string = (f'INSERT INTO HOST (hostId, type, created, lastSeen) VALUES ("pytest-client-{i}.uib.local", '
			f'"OpsiClient", "{now}", "{now}");')
		cursor.execute(sql_string)
		sql_string = ('INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority, setupScript, uninstallScript) '
			f'VALUES ("pytest-prod-{i}", "1.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT {i}", 60+{i}, "setup.opsiscript", "uninstall.opsiscript");')  # pylint: disable=line-too-long
		cursor.execute(sql_string)
		sql_string = f'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES ("pytest-prod-{i}", "1.0", "1", "{socket.getfqdn()}", "LocalbootProduct");' # pylint: disable=line-too-long
		cursor.execute(sql_string)

	cursor.execute(
		(
			'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) '
			'VALUES ("pytest-prod-1", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 1 version 2", 60);'
			'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) '
			'VALUES ("pytest-prod-4", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 4 version 2", 60);'
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

	create_depot_rpc(config.internal_url, "pytest-test-depot.uib.gmbh")
	create_depot_rpc(config.internal_url, "pytest-test-depot2.uib.gmbh")

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
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
			f'VALUES ("pytest-prod-4", "pytest-client-0.uib.local", "LocalbootProduct", "not_installed", "none", "none", "1.0", 1, "{now}");'
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
			f'VALUES ("pytest-prod-4", "pytest-client-1.uib.local", "LocalbootProduct", "not_installed", "none", "none", "1.0", 1, "{now}");'
			'INSERT INTO PRODUCT_ON_CLIENT '
			'(productId, clientId, productType, installationStatus, actionRequest, actionResult, productVersion, packageVersion, modificationTime) '
			f'VALUES ("pytest-prod-4", "pytest-client-4.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}");'

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
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) '
			'VALUES ("pytest-prod-3", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct");'
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) '
			'VALUES ("pytest-prod-4", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct");'
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) '
			'VALUES ("pytest-prod-3", "1.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct");'
			'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) '
			'VALUES ("pytest-prod-4", "2.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct");'
		)
	)

	# Product Group
	cursor.execute((
			'INSERT INTO opsi.GROUP (type, groupId) '
			'VALUES ("ProductGroup", "pytest-group-1");'
			'INSERT INTO opsi.GROUP (type, groupId) '
			'VALUES ("ProductGroup", "pytest-group-2");'
			'INSERT INTO OBJECT_TO_GROUP (groupType, groupId, objectId) '
			'VALUES ("ProductGroup", "pytest-group-1", "pytest-prod-0");'
			'INSERT INTO OBJECT_TO_GROUP (groupType, groupId, objectId) '
			'VALUES ("ProductGroup", "pytest-group-1", "pytest-prod-1");'
			'INSERT INTO OBJECT_TO_GROUP (groupType, groupId, objectId) '
			'VALUES ("ProductGroup", "pytest-group-1", "pytest-prod-2");'
			'INSERT INTO OBJECT_TO_GROUP (groupType, groupId, objectId) '
			'VALUES ("ProductGroup", "pytest-group-2", "pytest-prod-3");'
			'INSERT INTO OBJECT_TO_GROUP (groupType, groupId, objectId) '
			'VALUES ("ProductGroup", "pytest-group-2", "pytest-prod-4");'
		)
	)

	# Clients to Depots
	cursor.execute((
			'INSERT INTO CONFIG_STATE (configId, objectId, CONFIG_STATE.values) '
			'VALUES ("clientconfig.depot.id", "pytest-client-1.uib.local", \'["pytest-test-depot.uib.gmbh"]\');'
			'INSERT INTO CONFIG_STATE (configId, objectId, CONFIG_STATE.values) '
			'VALUES ("clientconfig.depot.id", "pytest-client-2.uib.local", \'["pytest-test-depot.uib.gmbh"]\');'
			'INSERT INTO CONFIG_STATE (configId, objectId, CONFIG_STATE.values) '
			'VALUES ("clientconfig.depot.id", "pytest-client-3.uib.local",	\'["pytest-test-depot2.uib.gmbh"]\');'
			'INSERT INTO CONFIG_STATE (configId, objectId, CONFIG_STATE.values) '
			'VALUES ("clientconfig.depot.id", "pytest-client-4.uib.local", \'["pytest-test-depot2.uib.gmbh"]\');'
		)
	)

	cursor.close()

	yield

	cursor = db.cursor()
	# cursor.execute(
	# 	(
	# 		'DELETE FROM PRODUCT_ON_DEPOT WHERE productId like "pytest%";'
	# 		'DELETE FROM PRODUCT_ON_CLIENT WHERE productId like "pytest%";'
	# 		'DELETE FROM OBJECT_TO_GROUP WHERE groupId like "pytest%";'
	# 		'DELETE FROM PRODUCT WHERE productId like "pytest%";'
	# 		'DELETE FROM HOST WHERE hostId like "pytest%";'
	# 		'DELETE FROM opsi.GROUP WHERE groupId like "pytest%";'
	# 		'DELETE FROM CONFIG_STATE WHERE objectId like "pytest%";'
	# 	)
	# )
	cursor.execute(
		(
			'DELETE FROM PRODUCT_ON_DEPOT;'
			'DELETE FROM PRODUCT_ON_CLIENT;'
			'DELETE FROM PRODUCT_PROPERTY_VALUE;'
			'DELETE FROM PRODUCT_PROPERTY;'
			'DELETE FROM PRODUCT_DEPENDENCY;'
			'DELETE FROM OBJECT_TO_GROUP;'
			'DELETE FROM PRODUCT;'
			'DELETE FROM HOST WHERE type!="OpsiConfigserver";'
			'DELETE FROM opsi.GROUP;'
			'DELETE FROM CONFIG_STATE;'
		)
	)
	cursor.close()

@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
