# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test utils
"""

import asyncio
import contextvars
import time
import types
from contextlib import asynccontextmanager, contextmanager
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any, AsyncGenerator, Dict, Generator, List, Tuple, Type, Union
from unittest.mock import patch

import aioredis
import msgpack  # type: ignore[import]
import MySQLdb  # type: ignore[import]
import pytest
import pytest_asyncio
import redis
from fastapi.testclient import TestClient
from MySQLdb.connections import Connection  # type: ignore[import]
from opsicommon.objects import LocalbootProduct, ProductOnDepot  # type: ignore[import]
from requests.cookies import cookiejar_from_dict
from starlette.testclient import WebSocketTestSession, _ASGIAdapter
from starlette.types import Receive, Scope, Send

from opsiconfd.application.main import BaseMiddleware, app
from opsiconfd.backend import BackendManager, get_mysql
from opsiconfd.config import Config
from opsiconfd.config import config as _config
from opsiconfd.utils import Singleton

ADMIN_USER = "adminuser"
ADMIN_PASS = "adminuser"
OPSI_SESSION_KEY = "opsiconfd:sessions"


def reset_singleton(cls: Singleton) -> None:
	"""Constructor will create a new instance afterwards"""
	if cls in cls._instances:  # pylint: disable=protected-access
		del cls._instances[cls]  # pylint: disable=protected-access


class WorkerMainLoopThread(Thread):
	def __init__(self) -> None:
		super().__init__()

		from opsiconfd.worker import Worker
		self.worker = Worker()

		self.loop = asyncio.new_event_loop()
		self.daemon = True
		self.stopped = Event()

	def stop(self) -> None:
		self.worker.stop()
		self.stopped.wait()

	def run(self) -> None:
		asyncio.set_event_loop(self.loop)
		self.loop.set_debug(True)
		asyncio.run(self.worker.main_loop())
		self.stopped.set()


@pytest_asyncio.fixture(autouse=True)
def worker_main_loop() -> Generator[None, None, None]:  # pylint: disable=redefined-outer-name
	wmlt = WorkerMainLoopThread()
	wmlt.start()
	yield None
	wmlt.stop()


class OpsiconfdTestClient(TestClient):
	def __init__(self) -> None:
		super().__init__(app, "https://opsiserver:4447")
		self.context: contextvars.Context | None = None
		self._address = ("127.0.0.1", 12345)

	def reset_cookies(self) -> None:
		self.cookies = cookiejar_from_dict({})  # type: ignore[no-untyped-call]

	def set_client_address(self, host: str, port: int) -> None:
		self._address = (host, port)

	def get_client_address(self) -> Tuple[str, int]:
		return self._address


@pytest.fixture()
def test_client() -> Generator[OpsiconfdTestClient, None, None]:
	client = OpsiconfdTestClient()

	def before_send(self: BaseMiddleware, scope: Scope, receive: Receive, send: Send) -> None:  # pylint: disable=unused-argument
		# Get the context out for later use
		client.context = contextvars.copy_context()

	def get_client_address(asgi_adapter: _ASGIAdapter, scope: Scope) -> Tuple[str, int]:  # pylint: disable=unused-argument
		return client.get_client_address()

	with (
		patch("opsiconfd.application.main.BaseMiddleware.get_client_address", get_client_address),
		patch("opsiconfd.application.main.BaseMiddleware.before_send", before_send),
	):
		yield client


@pytest.fixture
def config() -> Config:
	return _config


@contextmanager
def get_config(values: Union[Dict[str, Any], List[str]]) -> Generator[Config, None, None]:
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


CLEAN_REDIS_KEYS = (
	OPSI_SESSION_KEY,
	"opsiconfd:stats:client:failed_auth",
	"opsiconfd:stats:client:blocked",
	"opsiconfd:stats:client",
	"opsiconfd:stats:rpcs",
	"opsiconfd:stats:num_rpcs",
	"opsiconfd:stats:rpc",
	"opsiconfd:jsonrpccache:*:products",
	"opsiconfd:messagebus:*",
)


@asynccontextmanager
async def async_redis_client() -> AsyncGenerator[aioredis.StrictRedis, None]:  # pylint: disable=redefined-outer-name
	redis_client = aioredis.StrictRedis.from_url(_config.redis_internal_url)
	try:
		yield redis_client
	finally:
		await redis_client.close()


@contextmanager
def sync_redis_client() -> Generator[redis.StrictRedis, None, None]:  # pylint: disable=redefined-outer-name
	redis_client = redis.StrictRedis.from_url(_config.redis_internal_url)
	try:
		yield redis_client
	finally:
		redis_client.close()


async def async_clean_redis() -> None:
	async with async_redis_client() as redis_client:
		for redis_key in CLEAN_REDIS_KEYS:  # pylint: disable=loop-global-usage
			async for key in redis_client.scan_iter(f"{redis_key}:*"):
				await redis_client.delete(key)
			await redis_client.delete(redis_key)


def sync_clean_redis() -> None:
	with sync_redis_client() as redis_client:
		for redis_key in CLEAN_REDIS_KEYS:  # pylint: disable=loop-global-usage
			for key in redis_client.scan_iter(f"{redis_key}:*"):  # pylint: disable=loop-invariant-statement
				redis_client.delete(key)
			redis_client.delete(redis_key)


@pytest_asyncio.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis() -> AsyncGenerator[None, None]:  # pylint: disable=redefined-outer-name
	await async_clean_redis()
	yield None


@pytest_asyncio.fixture(autouse=True)
def clean_mysql() -> None:  # pylint: disable=redefined-outer-name
	mysql = get_mysql()  # pylint: disable=invalid-name
	with mysql.session() as session:
		session.execute("DELETE FROM HOST WHERE type='OpsiClient'")


def create_depot_jsonrpc(client: OpsiconfdTestClient, base_url: str, host_id: str, host_key: str = None) -> Dict[str, Any]:
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
def depot_jsonrpc(client: OpsiconfdTestClient, base_url: str, host_id: str, host_key: str = None) -> Generator[Dict[str, Any], None, None]:
	depot = create_depot_jsonrpc(client, base_url, host_id, host_key)
	try:
		yield depot
	finally:
		rpc = {"id": 1, "method": "host_delete", "params": [host_id]}
		client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)


@contextmanager
def client_jsonrpc(  # pylint: disable=too-many-arguments
	client: OpsiconfdTestClient, base_url: str, host_id: str, host_key: str = None, hardware_address: str = None, ip_address: str = None
) -> Generator[Dict[str, Any], None, None]:
	rpc = {"id": 1, "method": "host_createOpsiClient", "params": [host_id, host_key, "", "", hardware_address, ip_address]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()
	try:
		yield res.json()["result"]
	finally:
		rpc = {"id": 1, "method": "host_delete", "params": [host_id]}
		client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)


def create_products_jsonrpc(client: OpsiconfdTestClient, base_url: str, products: List[Dict[str, Any]]) -> None:
	products = [LocalbootProduct(**product).to_hash() for product in products]
	rpc = {"id": 1, "method": "product_createObjects", "params": [products]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()


def delete_products_jsonrpc(client: OpsiconfdTestClient, base_url: str, products: List[Dict[str, Any]]) -> None:
	products = [LocalbootProduct(**product).to_hash() for product in products]
	rpc = {"id": 1, "method": "product_deleteObjects", "params": [products]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()


@contextmanager
def products_jsonrpc(
	client: OpsiconfdTestClient,
	base_url: str,
	products: List[Dict[str, Any]],
	depots: List[str] | None = None
) -> Generator[None, None, None]:
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
					for product in products  # pylint: disable=loop-invariant-statement
				]
			)
		rpc = {"id": 1, "method": "productOnDepot_createObjects", "params": [product_on_depots]}
		res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
		res.raise_for_status()
	try:
		yield
	finally:
		delete_products_jsonrpc(client, base_url, products)


def create_poc_jsonrpc(  # pylint: disable=too-many-arguments
	http_client: OpsiconfdTestClient,
	base_url: str,
	opsi_client: str,
	product_id: str,
	install_state: str | None = None,
	action_request: str | None = None,
	action_result: str | None = None
) -> None:
	product = [product_id, "LocalbootProduct", opsi_client, install_state, action_request, None, None, action_result]  # pylint: disable=use-tuple-over-list
	rpc = {"id": 1, "method": "productOnClient_create", "params": product}
	res = http_client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()


def delete_poc_jsonrpc(
	http_client: OpsiconfdTestClient,
	base_url: str,
	opsi_client: str,
	product_id: str
) -> None:
	product = [product_id, opsi_client]  # pylint: disable=use-tuple-over-list
	rpc = {"id": 1, "method": "productOnClient_delete", "params": product}
	res = http_client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc, verify=False)
	res.raise_for_status()


@contextmanager
def poc_jsonrpc(  # pylint: disable=too-many-arguments
	http_client: OpsiconfdTestClient,
	base_url: str,
	opsi_client: str,
	product_id: str,
	install_state: str | None = None,
	action_request: str | None = None,
	action_result: str | None = None
) -> Generator[None, None, None]:
	create_poc_jsonrpc(http_client, base_url, opsi_client, product_id, install_state, action_request, action_result)
	try:
		yield
	finally:
		delete_poc_jsonrpc(http_client, base_url, opsi_client, product_id)


def get_one_depot_id_jsonrpc(client: OpsiconfdTestClient) -> str:
	rpc = {"id": 1, "method": "host_getIdents", "params": ["str", {"type": "OpsiDepotserver"}]}
	res = client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	return res.json()["result"][0]


def get_product_ordering_jsonrpc(client: OpsiconfdTestClient, depot_id: str) -> Dict[str, List[str]]:
	rpc = {"id": 1, "method": "getProductOrdering", "params": [depot_id, "algorithm1"]}
	res = client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	return res.json()["result"]


def get_dummy_products(count: int) -> List[Dict[str, Any]]:
	return [
		{"id": f"dummy-prod-{num}", "productVersion": "1.0", "packageVersion": "1", "name": "Dummy PRODUCT {num}", "priority": num % 8}
		for num in range(count)
	]


@pytest.fixture
def database_connection() -> Generator[Connection, None, None]:
	with open("tests/data/opsi-config/backends/mysql.conf", mode="r", encoding="utf-8") as conf:
		_globals: Dict[str, Any] = {}
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
def backend() -> BackendManager:
	return BackendManager()


class WebSocketMessageReader(Thread):
	def __init__(self, websocket: WebSocketTestSession, decode: bool = True) -> None:
		super().__init__()
		self.decode = decode
		self.daemon = True
		self.websocket = websocket
		self.messages: Queue[Dict[str, Any]] = Queue()
		self.should_stop = False

	def __enter__(self) -> "WebSocketMessageReader":
		self.start()
		return self

	def __exit__(
		self,
		exc_type: Type[BaseException] | None,
		exc_value: BaseException | None,
		traceback: types.TracebackType | None
	) -> None:
		self.stop()  # type: ignore[no-untyped-call]

	def run(self) -> None:
		while not self.should_stop:
			data = self.websocket.receive()
			if not data:
				continue
			if data["type"] == "websocket.close":
				break
			if data["type"] == "websocket.send":
				msg = data["bytes"]
				if self.decode:
					msg = msgpack.loads(msg)  # pylint: disable=dotted-import-in-loop
				# print(f"received: >>>{msg}<<<")
				self.messages.put(msg)

	def stop(self) -> None:
		self.should_stop = True

	def wait_for_message(self, timeout: float = 5.0) -> None:
		start = time.time()
		while True:
			if not self.messages.empty():
				return
			if time.time() - start >= timeout:  # pylint: disable=dotted-import-in-loop
				raise RuntimeError("timed out")  # pylint: disable=loop-invariant-statement
			time.sleep(0.1)  # pylint: disable=dotted-import-in-loop

	async def async_wait_for_message(self, timeout: float = 5.0) -> None:
		start = time.time()
		while True:
			if not self.messages.empty():
				return
			if time.time() - start >= timeout:  # pylint: disable=dotted-import-in-loop
				raise RuntimeError("timed out")  # pylint: disable=loop-invariant-statement
			await asyncio.sleep(0.1)  # pylint: disable=dotted-import-in-loop

	def get_messages(self) -> Generator[Union[Dict[str, Any], bytes], None, None]:
		try:
			while True:
				yield self.messages.get_nowait()
		except Empty:
			pass
