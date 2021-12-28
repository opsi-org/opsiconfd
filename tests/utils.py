# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
admininterface tests
"""

import sys
import socket
import json
from datetime import datetime, timedelta
import pytest
import redis
import aioredis
import requests
import MySQLdb
import urllib3

from OPSI.Backend.BackendManager import BackendManager

ADMIN_USER = "adminuser"
ADMIN_PASS = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"
MONITORING_CHECK_DAYS = 31


@pytest.fixture(autouse=True)
def disable_request_warning():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@pytest.fixture
def config(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel, redefined-outer-name
	return config


CLEAN_REDIS_KEYS = [
	OPSI_SESSION_KEY,
	"opsiconfd:stats:client:failed_auth",
	"opsiconfd:stats:client:blocked",
	"opsiconfd:stats:client",
	"opsiconfd:stats:rpcs",
	"opsiconfd:stats:num_rpcs",
	"opsiconfd:stats:rpc",
	"opsiconfd:jsonrpccache:*:products"
]
async def async_clean_redis(redis_url):
	redis_client = aioredis.StrictRedis.from_url(redis_url)
	for redis_key in CLEAN_REDIS_KEYS:
		async for key in redis_client.scan_iter(f"{redis_key}:*"):
			await redis_client.delete(key)
		await redis_client.delete(redis_key)


def sync_clean_redis(redis_url):
	redis_client = redis.StrictRedis.from_url(redis_url)
	for redis_key in CLEAN_REDIS_KEYS:
		for key in redis_client.scan_iter(f"{redis_key}:*"):
			redis_client.delete(key)
		redis_client.delete(redis_key)


@pytest.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis(config):  # pylint: disable=redefined-outer-name
	await async_clean_redis(config.redis_internal_url)
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
	res.raise_for_status()
	return res.json()

@pytest.fixture
def database_connection():
	with open("tests/opsi-config/backends/mysql.conf", mode="r", encoding="utf-8") as conf:
		_globals = {}
		exec(conf.read(), _globals)  # pylint: disable=exec-used
		mysql_config = _globals["config"]

	mysql = MySQLdb.connect(
		host=mysql_config["address"],
		user=mysql_config["username"],
		passwd=mysql_config["password"],
		db=mysql_config["database"],
		charset=mysql_config["databaseCharset"]
	)
	yield mysql
	mysql.close()

@pytest.fixture
def backend():
	return BackendManager(
		dispatchConfigFile="tests/opsi-config/backendManager/dispatch.conf",
		backendConfigDir="tests/opsi-config/backends"
	)

@pytest.fixture(autouse=True)
def create_check_data(config, database_connection):  # pylint: disable=redefined-outer-name
	mysql = database_connection
	mysql.autocommit(True)

	now = datetime.now()

	cursor = mysql.cursor()
	cursor.execute((
		'DELETE FROM PRODUCT_ON_DEPOT;'
		'DELETE FROM PRODUCT_ON_CLIENT;'
		'DELETE FROM PRODUCT_PROPERTY_VALUE;'
		'DELETE FROM PRODUCT_PROPERTY;'
		'DELETE FROM PRODUCT_DEPENDENCY;'
		'DELETE FROM OBJECT_TO_GROUP;'
		'DELETE FROM PRODUCT;'
		'DELETE FROM HOST WHERE type != "OpsiConfigserver";'
		'DELETE FROM `GROUP`;'
		'DELETE FROM CONFIG_STATE WHERE objectId like "pytest%";'
	))

	# Product
	for i in range(5):
		cursor.execute(
			f'INSERT INTO HOST (hostId, `type`, created, lastSeen, hardwareAddress, `description`, notes, inventoryNumber) '
			f'VALUES ("pytest-client-{i}.uib.local", "OpsiClient", "{now}", "{now}", "af:fe:af:fe:af:f{i}", "description client{i}", "notes client{i}", "{i}");'
		)
		cursor.execute(
			'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority, setupScript, uninstallScript) VALUES '
			f'("pytest-prod-{i}", "1.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT {i}", 60+{i}, "setup.opsiscript", "uninstall.opsiscript");'
		)
		cursor.execute(
			f'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES '
			f'("pytest-prod-{i}", "1.0", "1", "{socket.getfqdn()}", "LocalbootProduct");'
		)

	cursor.execute(
		'INSERT INTO PRODUCT (productId, productVersion, packageVersion, type,  name, priority) VALUES  '
		'("pytest-prod-1", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 1 version 2", 60),'
		'("pytest-prod-4", "2.0", "1", "LocalbootProduct", "Pytest dummy PRODUCT 4 version 2", 60);'
	)

	# Host
	cursor.execute(
		'INSERT INTO HOST (hostId, type, created, lastSeen) VALUES '
		f'("pytest-lost-client.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}"),'
		f'("pytest-lost-client-fp.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}"),'
		f'("pytest-lost-client-fp2.uib.local", "OpsiClient", "{now}", "{now-timedelta(days=MONITORING_CHECK_DAYS)}");'
	)

	create_depot_rpc(config.internal_url, "pytest-test-depot.uib.gmbh")
	create_depot_rpc(config.internal_url, "pytest-test-depot2.uib.gmbh")

	# Product on client
	cursor.execute(
		'INSERT INTO PRODUCT_ON_CLIENT '
		'(productId, clientId, productType, installationStatus, actionRequest, actionResult, '
		' productVersion, packageVersion, modificationTime) VALUES '
		f'("pytest-prod-1", "pytest-client-1.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}"),'
		f'("pytest-prod-2", "pytest-client-2.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}"),'
		f'("pytest-prod-3", "pytest-client-3.uib.local", "LocalbootProduct", "installed", "none", "none", "1.0", 1, "{now}"),'
		f'("pytest-prod-2", "pytest-lost-client-fp.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}"),'
		f'("pytest-prod-2", "pytest-lost-client-fp2.uib.local", "LocalbootProduct", "unknown", "none", "failed", "1.0", 1, "{now}"),'
		f'("pytest-prod-1", "pytest-lost-client-fp2.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}"),'
		f'("pytest-prod-4", "pytest-client-0.uib.local", "LocalbootProduct", "not_installed", "none", "none", "1.0", 1, "{now}"),'
		f'("pytest-prod-4", "pytest-client-1.uib.local", "LocalbootProduct", "not_installed", "none", "none", "1.0", 1, "{now}"),'
		f'("pytest-prod-4", "pytest-client-4.uib.local", "LocalbootProduct", "not_installed", "setup", "none", "1.0", 1, "{now}");'
	)


	# Product on depot
	cursor.execute(
		'INSERT INTO PRODUCT_ON_DEPOT (productId, productVersion, packageVersion, depotId, productType) VALUES '
		'("pytest-prod-1", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-2", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-1", "2.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-2", "1.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-3", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-4", "1.0", "1", "pytest-test-depot.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-3", "1.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct"),'
		'("pytest-prod-4", "2.0", "1", "pytest-test-depot2.uib.gmbh", "LocalbootProduct");'
	)

	# Product Group
	cursor.execute(
		'INSERT INTO `GROUP` (type, groupId) VALUES '
		'("ProductGroup", "pytest-group-1"),'
		'("ProductGroup", "pytest-group-2");'
	)
	cursor.execute(
		'INSERT INTO OBJECT_TO_GROUP (groupType, groupId, objectId) VALUES '
		'("ProductGroup", "pytest-group-1", "pytest-prod-0"),'
		'("ProductGroup", "pytest-group-1", "pytest-prod-1"),'
		'("ProductGroup", "pytest-group-1", "pytest-prod-2"),'
		'("ProductGroup", "pytest-group-2", "pytest-prod-3"),'
		'("ProductGroup", "pytest-group-2", "pytest-prod-4");'
	)

	# Clients to Depots
	cursor.execute(
		'INSERT INTO CONFIG_STATE (configId, objectId, CONFIG_STATE.values) VALUES '
		'("clientconfig.depot.id", "pytest-client-1.uib.local", \'["pytest-test-depot.uib.gmbh"]\'),'
		'("clientconfig.depot.id", "pytest-client-2.uib.local", \'["pytest-test-depot.uib.gmbh"]\'),'
		'("clientconfig.depot.id", "pytest-client-3.uib.local",	\'["pytest-test-depot2.uib.gmbh"]\'),'
		'("clientconfig.depot.id", "pytest-client-4.uib.local", \'["pytest-test-depot2.uib.gmbh"]\');'
	)

	cursor.close()

	yield

	cursor = mysql.cursor()
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
		'DELETE FROM PRODUCT_ON_DEPOT;'
		'DELETE FROM PRODUCT_ON_CLIENT;'
		'DELETE FROM PRODUCT_PROPERTY_VALUE;'
		'DELETE FROM PRODUCT_PROPERTY;'
		'DELETE FROM PRODUCT_DEPENDENCY;'
		'DELETE FROM OBJECT_TO_GROUP;'
		'DELETE FROM PRODUCT;'
		'DELETE FROM HOST WHERE type!="OpsiConfigserver";'
		'DELETE FROM `GROUP`;'
		'DELETE FROM CONFIG_STATE;'
	)
