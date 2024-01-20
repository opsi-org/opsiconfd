# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test utils
"""

from __future__ import annotations

import asyncio
import contextvars
import time
import types
from contextlib import asynccontextmanager, contextmanager
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any, AsyncGenerator, Generator, Type, Union
from unittest.mock import patch

import msgpack  # type: ignore[import]
import MySQLdb  # type: ignore[import]
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx._auth import BasicAuth
from MySQLdb.connections import Connection  # type: ignore[import]
from opsicommon.objects import LocalbootProduct, ProductOnDepot, deserialize, serialize  # type: ignore[import]
from redis import Redis
from redis.asyncio import Redis as AsyncRedis
from requests.cookies import cookiejar_from_dict
from starlette.testclient import WebSocketTestSession
from starlette.types import Receive, Scope, Send

from opsiconfd.application import app
from opsiconfd.application.main import BaseMiddleware
from opsiconfd.backend import get_unprotected_backend
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.rpc.main import UnprotectedBackend
from opsiconfd.config import Config, OpsiConfig
from opsiconfd.config import config as _config
from opsiconfd.config import opsi_config as _opsi_config
from opsiconfd.utils import Singleton
from opsiconfd.worker import Worker

ADMIN_USER = "adminuser"
ADMIN_PASS = "adminuser"


def reset_singleton(cls: Singleton) -> None:
	"""Constructor will create a new instance afterwards"""
	if cls in cls._instances:  # pylint: disable=protected-access
		del cls._instances[cls]  # pylint: disable=protected-access


class OpsiconfdTestClient(TestClient):
	def __init__(self) -> None:
		super().__init__(app, "https://opsiserver:4447")
		self.context: contextvars.Context | None = None
		self._address = ("127.0.0.1", 12345)
		self._username: str | None = None
		self._password: str | None = None

	@property  # type: ignore[override]
	def auth(self) -> tuple[str, str] | None:
		if self._username is None or self._password is None:
			return None
		return self._username, self._password

	@auth.setter
	def auth(self, basic_auth: tuple[str, str] | None) -> None:
		if basic_auth is None:
			self._username = self._password = None
			self._auth = None
		else:
			self._username, self._password = basic_auth
			self._auth = BasicAuth(self._username, self._password)

	def reset_cookies(self) -> None:
		self.cookies = cookiejar_from_dict({})  # type: ignore[no-untyped-call]

	def set_client_address(self, host: str, port: int) -> None:
		self._address = (host, port)

	def get_client_address(self) -> tuple[str, int]:
		return self._address

	def jsonrpc20(self, method: str, params: dict[str, Any] | list[Any] | None = None) -> Any:
		params = serialize(params or {})
		rpc = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
		print(self._username, self._password)
		return deserialize(self.post("/rpc", json=rpc).json(), deep=True)


@pytest.fixture()
def test_client() -> Generator[OpsiconfdTestClient, None, None]:
	client = OpsiconfdTestClient()

	def before_send(self: BaseMiddleware, scope: Scope, receive: Receive, send: Send) -> None:  # pylint: disable=unused-argument
		# Get the context out for later use
		client.context = contextvars.copy_context()

	def get_client_address(asgi_adapter: Any, scope: Scope) -> tuple[str, int]:  # pylint: disable=unused-argument
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
def get_config(values: Union[dict[str, Any], list[str]]) -> Generator[Config, None, None]:
	conf = _config._config.__dict__.copy()  # pylint: disable=protected-access
	args = _config._args.copy()  # pylint: disable=protected-access
	try:
		if isinstance(values, dict):
			_config._config.__dict__.update(values)  # pylint: disable=protected-access
			_config._update_config()  # pylint: disable=protected-access
		else:
			_config._set_args(values)  # pylint: disable=protected-access
			_config._parse_args()  # pylint: disable=protected-access
		yield _config
	finally:
		_config._config.__dict__ = conf  # pylint: disable=protected-access
		_config._args = args  # pylint: disable=protected-access


@pytest.fixture
def opsi_config() -> OpsiConfig:
	return _opsi_config


@contextmanager
def get_opsi_config(values: list[dict[str, Any]]) -> Generator[OpsiConfig, None, None]:
	try:
		for value in values:
			_opsi_config.set(value["category"], value["config"], value=value["value"])  # pylint: disable=protected-access
		yield _opsi_config
	finally:
		_opsi_config.read_config_file()


@asynccontextmanager
async def async_redis_client() -> AsyncGenerator[AsyncRedis, None]:  # pylint: disable=redefined-outer-name
	redis_client: AsyncRedis = AsyncRedis.from_url(_config.redis_internal_url)
	try:
		yield redis_client
	finally:
		await redis_client.aclose()  # type: ignore[attr-defined]


@contextmanager
def sync_redis_client() -> Generator[Redis, None, None]:  # pylint: disable=redefined-outer-name
	redis_client = Redis.from_url(_config.redis_internal_url)
	try:
		yield redis_client
	finally:
		redis_client.close()


async def async_clean_redis() -> None:
	async with async_redis_client() as redis_client:
		async for key in redis_client.scan_iter(f"{_config.redis_key()}:*"):
			await redis_client.delete(key)


def sync_clean_redis() -> None:
	with sync_redis_client() as redis_client:
		for key in redis_client.scan_iter(f"{_config.redis_key()}:*"):
			redis_client.delete(key)


@pytest_asyncio.fixture(autouse=True)
@pytest.mark.asyncio
async def clean_redis() -> AsyncGenerator[None, None]:  # pylint: disable=redefined-outer-name
	await async_clean_redis()
	yield None


@pytest.fixture
def worker_state() -> None:
	worker = Worker._instance  # pylint: disable=protected-access
	if not worker:
		raise RuntimeError("No worker instance")
	with sync_redis_client() as rclient:
		rclient.hset(
			f"{_config.redis_key('state')}:workers:{_config.node_name}:{worker.worker_num}",
			key=None,
			value=None,
			mapping={"worker_pid": worker.pid, "node_name": _config.node_name, "worker_num": worker.worker_num},
		)


def delete_mysql_data() -> None:  # pylint: disable=redefined-outer-name
	mysql = MySQLConnection()  # pylint: disable=invalid-name
	with mysql.connection():
		with mysql.session() as session:
			session.execute("DELETE FROM `PRODUCT_ON_CLIENT`")
			session.execute("DELETE FROM `PRODUCT_ON_DEPOT`")
			session.execute("DELETE FROM `PRODUCT_DEPENDENCY`")
			session.execute("DELETE FROM `PRODUCT_PROPERTY_VALUE`")
			session.execute("DELETE FROM `PRODUCT_PROPERTY`")
			session.execute("DELETE FROM `PRODUCT`")
			session.execute("DELETE FROM `OBJECT_TO_GROUP`")
			session.execute("DELETE FROM `GROUP`")
			session.execute("DELETE FROM `CONFIG_STATE`")
			session.execute("DELETE FROM `HOST` WHERE type != 'OpsiConfigserver'")
			session.execute("DELETE FROM `USER`")


@pytest_asyncio.fixture(autouse=True)
def clean_mysql() -> None:  # pylint: disable=redefined-outer-name
	delete_mysql_data()


def create_depot_jsonrpc(client: OpsiconfdTestClient, base_url: str, host_id: str, host_key: str | None = None) -> dict[str, Any]:
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
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	return res.json()["result"]


@contextmanager
def depot_jsonrpc(
	client: OpsiconfdTestClient, base_url: str, host_id: str, host_key: str | None = None
) -> Generator[dict[str, Any], None, None]:
	depot = create_depot_jsonrpc(client, base_url, host_id, host_key)
	try:
		yield depot
	finally:
		rpc = {"id": 1, "method": "host_delete", "params": [host_id]}
		client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)


@contextmanager
def client_jsonrpc(  # pylint: disable=too-many-arguments
	client: OpsiconfdTestClient,
	base_url: str,
	host_id: str,
	host_key: str | None = None,
	hardware_address: str | None = None,
	ip_address: str | None = None,
) -> Generator[dict[str, Any], None, None]:
	rpc = {"id": 1, "method": "host_createOpsiClient", "params": [host_id, host_key, "", "", hardware_address, ip_address]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	try:
		yield res.json()["result"]
	finally:
		rpc = {"id": 1, "method": "host_delete", "params": [host_id]}
		client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)


def create_products_jsonrpc(client: OpsiconfdTestClient, base_url: str, products: list[dict[str, Any]]) -> None:
	products = [LocalbootProduct(**product).to_hash() for product in products]
	rpc = {"id": 1, "method": "product_createObjects", "params": [products]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()


def delete_products_jsonrpc(client: OpsiconfdTestClient, base_url: str, products: list[dict[str, Any]]) -> None:
	products = [LocalbootProduct(**product).to_hash() for product in products]
	rpc = {"id": 1, "method": "product_deleteObjects", "params": [products]}
	res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()


@contextmanager
def products_jsonrpc(
	client: OpsiconfdTestClient, base_url: str, products: list[dict[str, Any]], depots: list[str] | None = None
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
					for product in products
				]
			)
		rpc = {"id": 1, "method": "productOnDepot_createObjects", "params": [product_on_depots]}
		res = client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
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
	action_result: str | None = None,
) -> None:
	product = [product_id, "LocalbootProduct", opsi_client, install_state, action_request, None, None, action_result]
	rpc = {"id": 1, "method": "productOnClient_create", "params": product}
	res = http_client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()


def delete_poc_jsonrpc(http_client: OpsiconfdTestClient, base_url: str, opsi_client: str, product_id: str) -> None:
	product = [product_id, opsi_client]
	rpc = {"id": 1, "method": "productOnClient_delete", "params": product}
	res = http_client.post(f"{base_url}/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()


@contextmanager
def poc_jsonrpc(  # pylint: disable=too-many-arguments
	http_client: OpsiconfdTestClient,
	base_url: str,
	opsi_client: str,
	product_id: str,
	install_state: str | None = None,
	action_request: str | None = None,
	action_result: str | None = None,
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


def get_product_ordering_jsonrpc(client: OpsiconfdTestClient, depot_id: str) -> dict[str, list[str]]:
	rpc = {"id": 1, "method": "getProductOrdering", "params": [depot_id]}
	res = client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	return res.json()["result"]


def get_dummy_products(count: int) -> list[dict[str, Any]]:
	return [
		{
			"id": f"dummy-prod-{num}",
			"productVersion": "1.0",
			"packageVersion": "1",
			"name": "Dummy PRODUCT {num}",
			"priority": num % 8,
			"setupScript": "setup.opsiscript",
		}
		for num in range(count)
	]


@pytest.fixture
def database_connection() -> Generator[Connection, None, None]:
	with open("tests/data/opsi-config/backends/mysql.conf", mode="r", encoding="utf-8") as conf:
		_globals: dict[str, Any] = {}
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
def backend() -> UnprotectedBackend:
	return get_unprotected_backend()


class WebSocketMessageReader(Thread):
	def __init__(self, websocket: WebSocketTestSession, decode: bool = True, print_raw_data: int = 32) -> None:
		super().__init__()
		self.decode = decode
		self.daemon = True
		self.print_raw_data = print_raw_data
		self.websocket = websocket
		self.messages: Queue[dict[str, Any] | bytes] = Queue()
		self.should_stop = False
		self.running = Event()

	def __enter__(self) -> WebSocketMessageReader:
		self.start()
		return self

	def __exit__(
		self, exc_type: Type[BaseException] | None, exc_value: BaseException | None, traceback: types.TracebackType | None
	) -> None:
		self.stop()  # type: ignore[no-untyped-call]

	def run(self) -> None:
		while not self.should_stop:
			self.running.set()
			data = self.websocket.receive()
			if self.should_stop:
				break
			if not data:
				continue
			if data["type"] == "websocket.close":
				break
			if data["type"] == "websocket.send":
				raw = data["bytes"]
				if self.decode:
					msg = msgpack.loads(raw)
				else:
					msg = raw
				self.messages.put(msg)
				if self.print_raw_data:
					print(
						f"WebSocketMessageReader received message (size: {len(raw)}, raw: {raw[:self.print_raw_data]}...), qsize: {self.messages.qsize()}"
					)

	def stop(self) -> None:
		self.should_stop = True
		self.websocket._send_queue.put({})  # pylint: disable=protected-access
		self.join(3)

	def purge_messages(self) -> None:
		try:
			while True:
				self.messages.get_nowait()
		except Empty:
			pass

	def wait_for_message(self, count: int = 1, timeout: float = 5.0, error_on_timeout: bool = True) -> None:
		print(f"WebSocketMessageReader waiting for {count} messages with timeout {timeout}")
		start = time.time()
		while True:
			if self.messages.qsize() >= count:
				return
			if time.time() - start >= timeout:
				if error_on_timeout:
					messages = []
					try:
						while True:
							messages.append(self.messages.get_nowait())
					except Empty:
						pass
					raise RuntimeError(
						f"Timed out while waiting for messages (got {len(messages)}, expected {count})\nMessages: {messages}"
					)
				print(f"Timed out while waiting for messages (got {self.messages.qsize()}, expected {count} max)")
				return
			time.sleep(0.1)

	async def async_wait_for_message(self, count: int = 1, timeout: float = 5.0, error_on_timeout: bool = True) -> None:
		print(f"WebSocketMessageReader waiting for {count} messages with timeout {timeout}")
		start = time.time()
		while True:
			if self.messages.qsize() >= count:
				return
			if time.time() - start >= timeout:
				if error_on_timeout:
					messages = []
					try:
						while True:
							messages.append(self.messages.get_nowait())
					except Empty:
						pass
					raise RuntimeError(
						f"Timed out while waiting for messages (got {len(messages)}, expected {count})\nMessages: {messages}"
					)
				print(f"Timed out while waiting for messages (got {self.messages.qsize()}, expected {count} max)")
				return
			await asyncio.sleep(0.1)

	def get_messages(self) -> Generator[dict[str, Any], None, None]:
		try:
			while True:
				msg = self.messages.get_nowait()
				assert isinstance(msg, dict)
				yield msg
		except Empty:
			pass

	def get_raw_messages(self) -> Generator[bytes, None, None]:
		try:
			while True:
				msg = self.messages.get_nowait()
				assert isinstance(msg, bytes)
				yield msg
		except Empty:
			pass


ACL_CONF_41 = """# -*- coding: utf-8 -*-
#
# = = = = = = = = = = = = = = = = = = = =
# =      backend acl configuration      =
# = = = = = = = = = = = = = = = = = = = =
#
# This file configures access control to protected backend methods.
# Entries has to follow the form:
# <regular expression to match method name(s)> : <semicolon separated list of acl entries>
#
# acl enrties are specified like:
# <entry type>[(<comma separated list of names/ids>[,attributes(<comma separated list of allowed/denied attributes>)])]
#
# For every method the first entry which allows (partial) access is decisive.
#
# Possible types of entries are:
#    all                : everyone
#    sys_user           : a system user
#    sys_group          : a system group
#    opsi_depotserver   : an opsi depot server
#    opsi_client        : an opsi client
#    self               : the object to be read or written
#
# Examples:
#    host_getObjects : self
#       allow clients to read their own host objects
#    host_deleteObjects : sys_user(admin,opsiadmin),sys_group(opsiadmins)
#       allow system users "admin", "opsiadmin" and members of system group "opsiadmins" to delete hosts
#    product_.* : opsi_client(client1.uib.local),opsi_depotserver
#       allow access to product objects to opsi client "client1.uib.local" and all opsi depot servers
#    host_getObjects : sys_user(user1,attributes(id,description,notes))
#       allow partial access to host objects to system user "user1". "user1" is allowed to read object attributes "id", "description", "notes"
#    host_getObjects : sys_group(group1,attributes(!opsiHostKey))
#       allow partial access to host objects to members of system group "group1". Members are allowed to read all object attributes except "opsiHostKey"

backend_deleteBase     : sys_group(opsiadmin)
backend_.*             : all
hostControl.*          : sys_group(opsiadmin); opsi_depotserver
host_get.*             : sys_group(opsiadmin); opsi_depotserver; self; opsi_client(attributes(!opsiHostKey,!description,!lastSeen,!notes,!hardwareAddress,!inventoryNumber))
auditSoftware_delete.* : sys_group(opsiadmin); opsi_depotserver
auditSoftware_.*       : sys_group(opsiadmin); opsi_depotserver; opsi_client
auditHardware_delete.* : sys_group(opsiadmin); opsi_depotserver
auditHardware_.*       : sys_group(opsiadmin); opsi_depotserver; opsi_client
user_setCredentials    : sys_group(opsiadmin); opsi_depotserver
user_getCredentials    : opsi_depotserver; opsi_client
.*_get.*               : sys_group(opsiadmin); opsi_depotserver; opsi_client
get(Raw){0,1}Data      : sys_group(opsiadmin); opsi_depotserver
.*                     : sys_group(opsiadmin); opsi_depotserver; self
"""
