# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test utils
"""

from typing import Dict, Any, Union, List
from contextlib import contextmanager, asynccontextmanager
import contextvars
from unittest.mock import patch

import pytest
import pytest_asyncio
import redis
import aioredis
import MySQLdb  # type: ignore[import]
from requests.cookies import cookiejar_from_dict
from fastapi.testclient import TestClient

from opsicommon.objects import LocalbootProduct, ProductOnDepot  # type: ignore[import]

from opsiconfd.utils import Singleton
from opsiconfd.config import config as _config
from opsiconfd.application.main import app
from opsiconfd.backend import BackendManager


ADMIN_USER = "adminuser"
ADMIN_PASS = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"


def reset_singleton(cls: Singleton) -> None:
	"""Constructor will create a new instance afterwards"""
	if cls in cls._instances:  # pylint: disable=protected-access
		del cls._instances[cls]  # pylint: disable=protected-access


@pytest.fixture
def config():
	return _config


@contextmanager
def get_config(values: Union[Dict[str, Any], List[str]]):
	conf = _config._config.__dict__.copy()  # pylint: disable=protected-access
	args = _config._args.copy()  # pylint: disable=protected-access
	try:
		if isinstance(values, dict):
			_config._config.__dict__.update(values)  # pylint: disable=protected-access
		else:
			_config._set_args(values)  # pylint: disable=protected-access
			_config._parse_args()  # pylint: disable=protected-access
		yield _config
	finally:
		_config._config.__dict__ = conf  # pylint: disable=protected-access
		_config._args = args  # pylint: disable=protected-access


CLEAN_REDIS_KEYS = [
	OPSI_SESSION_KEY,
	"opsiconfd:stats:client:failed_auth",
	"opsiconfd:stats:client:blocked",
	"opsiconfd:stats:client",
	"opsiconfd:stats:rpcs",
	"opsiconfd:stats:num_rpcs",
	"opsiconfd:stats:rpc",
	"opsiconfd:jsonrpccache:*:products",
]


@asynccontextmanager
async def async_redis_client():  # pylint: disable=redefined-outer-name
	redis_client = aioredis.StrictRedis.from_url(_config.redis_internal_url)
	try:
		yield redis_client
	finally:
		await redis_client.close()


@contextmanager
def sync_redis_client():  # pylint: disable=redefined-outer-name
	redis_client = redis.StrictRedis.from_url(_config.redis_internal_url)
	try:
		yield redis_client
	finally:
		redis_client.close()


async def async_clean_redis():
	async with async_redis_client() as redis_client:
		for redis_key in CLEAN_REDIS_KEYS:
			async for key in redis_client.scan_iter(f"{redis_key}:*"):
				await redis_client.delete(key)
			await redis_client.delete(redis_key)


def sync_clean_redis():
	with sync_redis_client() as redis_client:
		for redis_key in CLEAN_REDIS_KEYS:
			for key in redis_client.scan_iter(f"{redis_key}:*"):
				redis_client.delete(key)
			redis_client.delete(redis_key)


@pytest_asyncio.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis():  # pylint: disable=redefined-outer-name
	await async_clean_redis()
	yield None


def create_depot_jsonrpc(client, base_url: str, host_id: str, host_key: str = None):
	rpc = {
		"id": 1,
		"method": "host_createOpsiDepotserver",
		"params": [
			host_id,
			host_key,
			"file:///var/lib/opsi/depot",
			"smb://172.17.0.101/opsi_depot",
			None,
			"file:///var/lib/opsi/repository",
			"webdavs://172.17.0.101:4447/repository",
		],
	}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()
	return res.json()["result"]


@contextmanager
def depot_jsonrpc(client, base_url: str, host_id: str, host_key: str = None):
	depot = create_depot_jsonrpc(client, base_url, host_id, host_key)
	try:
		yield depot
	finally:
		rpc = {"id": 1, "method": "host_delete", "params": [host_id]}
		client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)


@contextmanager
def client_jsonrpc(
	client, base_url: str, host_id: str, host_key: str = None, hardware_address: str = None, ip_address: str = None
):  # pylint: disable=too-many-arguments
	rpc = {"id": 1, "method": "host_createOpsiClient", "params": [host_id, host_key, "", "", hardware_address, ip_address]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()
	try:
		yield res.json()["result"]
	finally:
		rpc = {"id": 1, "method": "host_delete", "params": [host_id]}
		client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)


def create_products_jsonrpc(client, base_url, products):
	products = [LocalbootProduct(**product).to_hash() for product in products]
	rpc = {"id": 1, "method": "product_createObjects", "params": [products]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()


def delete_products_jsonrpc(client, base_url, products):
	products = [LocalbootProduct(**product).to_hash() for product in products]
	rpc = {"id": 1, "method": "product_deleteObjects", "params": [products]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()


@contextmanager
def products_jsonrpc(client, base_url, products, depots=None):
	create_products_jsonrpc(client, base_url, products)
	if depots:
		product_on_depots = []
		for depot_id in depots:
			product_on_depots.extend(
				[
					ProductOnDepot(
						productType="LocalbootProduct",
						productId=product["id"],
						productVersion=product["productVersion"],
						packageVersion=product["packageVersion"],
						depotId=depot_id,
					).to_hash()
					for product in products
				]
			)
		rpc = {"id": 1, "method": "productOnDepot_createObjects", "params": [product_on_depots]}
		res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
		res.raise_for_status()
	try:
		yield
	finally:
		delete_products_jsonrpc(client, base_url, products)


def create_poc_jsonrpc(
	http_client, base_url, opsi_client, product_id, install_state=None, action_request=None, action_result=None
):  # pylint: disable=too-many-arguments
	product = [product_id, "LocalbootProduct", opsi_client, install_state, action_request, None, None, action_result]
	rpc = {"id": 1, "method": "productOnClient_create", "params": product}
	res = http_client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()


def delete_poc_jsonrpc(http_client, base_url, opsi_client, product_id):
	product = [product_id, opsi_client]
	rpc = {"id": 1, "method": "productOnClient_delete", "params": product}
	res = http_client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()


@contextmanager
def poc_jsonrpc(
	http_client, base_url, opsi_client, product_id, install_state=None, action_request=None, action_result=None
):  # pylint: disable=too-many-arguments
	create_poc_jsonrpc(http_client, base_url, opsi_client, product_id, install_state, action_request, action_result)
	try:
		yield
	finally:
		delete_poc_jsonrpc(http_client, base_url, opsi_client, product_id)


def get_one_depot_id_jsonrpc(client):
	rpc = {"id": 1, "method": "host_getIdents", "params": ["str", {"type": "OpsiDepotserver"}]}
	res = client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	return res.json()["result"][0]


def get_product_ordering_jsonrpc(client, depot_id):
	rpc = {"id": 1, "method": "getProductOrdering", "params": [depot_id, "algorithm1"]}
	res = client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	return res.json()["result"]


def get_dummy_products(count: int) -> List[Dict]:
	products = []
	for num in range(count):
		products.append(
			{"id": f"dummy-prod-{num}", "productVersion": "1.0", "packageVersion": "1", "name": "Dummy PRODUCT {num}", "priority": num % 8}
		)
	return products


@pytest.fixture
def database_connection():
	with open("tests/data/opsi-config/backends/mysql.conf", mode="r", encoding="utf-8") as conf:
		_globals = {}
		exec(conf.read(), _globals)  # pylint: disable=exec-used
		mysql_config = _globals["config"]

	mysql = MySQLdb.connect(
		host=mysql_config["address"],
		user=mysql_config["username"],
		passwd=mysql_config["password"],
		db=mysql_config["database"],
		charset=mysql_config["databaseCharset"],
	)
	yield mysql
	mysql.close()


@pytest.fixture()
def backend():
	return BackendManager()


@pytest.fixture()
def test_client():
	class OpsiconfdTestClient(TestClient):
		def __init__(self) -> None:
			super().__init__(app, "https://opsiserver:4447")
			self.context = None
			self._address = ("127.0.0.1", 12345)

		def reset_cookies(self):
			self.cookies = cookiejar_from_dict({})

		def set_client_address(self, host, port):
			self._address = (host, port)

		def get_client_address(self):
			return self._address

	client = OpsiconfdTestClient()

	def before_send(self, scope, receive, send):  # pylint: disable=unused-argument
		# Get the context out for later use
		client.context = contextvars.copy_context()

	def get_client_address(asgi_adapter, scope):  # pylint: disable=unused-argument
		return client.get_client_address()

	with (
		patch("opsiconfd.application.main.BaseMiddleware.get_client_address", get_client_address),
		patch("opsiconfd.application.main.BaseMiddleware.before_send", before_send),
	):
		yield client
