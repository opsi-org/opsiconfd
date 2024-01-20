# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test admininterface
"""

import json
import os
import sys
import tempfile
from types import ModuleType
from typing import Any, Callable
from unittest.mock import patch

import pytest
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.requests import Request

from opsiconfd.addon.manager import AddonManager
from opsiconfd.config import FQDN
from opsiconfd.redis import ip_address_to_redis_key

from .test_addon_manager import cleanup  # pylint: disable=unused-import
from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	client_jsonrpc,
	config,
	depot_jsonrpc,
	get_config,
	products_jsonrpc,
	sync_redis_client,
	test_client,
)


def set_failed_auth_and_blocked(conf: Config, ip_address: str) -> None:  # pylint: disable=redefined-outer-name
	with sync_redis_client() as redis:
		ip_address_redis = ip_address_to_redis_key(ip_address)
		redis.execute_command(
			f"ts.create {conf.redis_key('stats')}:client:failed_auth:{ip_address_redis} "
			f"RETENTION 86400000 LABELS client_addr {ip_address}"
		)
		redis.execute_command(
			f"ts.add {conf.redis_key('stats')}:client:failed_auth:{ip_address_redis} "
			f"* 11 RETENTION 86400000 LABELS client_addr {ip_address}"
		)
		redis.set(f"{conf.redis_key('stats')}:client:blocked:{ip_address_redis}", 1)


def call_rpc(client: OpsiconfdTestClient, rpc_request_data: list, expect_error: list) -> None:
	for idx, data in enumerate(rpc_request_data):
		result = client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=data)
		assert result.status_code == 200
		result_json = result.json()
		if expect_error[idx]:
			assert result_json.get("result") is None
		else:
			assert result_json.get("result") is not None
			assert result_json.get("error") is None


@pytest.fixture(name="admininterface")
def fixture_admininterface(monkeypatch: Any) -> ModuleType:
	monkeypatch.setattr(sys, "argv", ["opsiconfd"])
	import opsiconfd.application.admininterface as ai  # pylint: disable=import-outside-toplevel

	return ai


def test_unblock_all_request(  # pylint: disable=redefined-outer-name,unused-argument
	test_client: OpsiconfdTestClient,
	config: Config,
) -> None:
	with sync_redis_client() as redis:
		addresses = ("10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888")
		for test_ip in addresses:
			set_failed_auth_and_blocked(config, test_ip)

		res = test_client.post("/admin/unblock-all", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200

		for test_ip in addresses:
			val = redis.get(f"{config.redis_key('stats')}:client:blocked:{ip_address_to_redis_key(test_ip)}")
			assert not val


@pytest.mark.asyncio
async def test_unblock_all(config: Config, admininterface: ModuleType) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	with sync_redis_client() as redis:
		addresses = ("10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888")

		for test_ip in addresses:
			set_failed_auth_and_blocked(config, test_ip)

		response = await admininterface.unblock_all_clients()
		print(response)
		print(response.__dict__)
		assert response.status_code == 200
		response_body = json.loads(response.body)
		assert response_body.get("error") is None
		assert sorted(response_body["clients"]) == sorted(addresses)

		for test_ip in addresses:
			val = redis.get(f"{config.redis_key('stats')}:client:blocked:{ip_address_to_redis_key(test_ip)}")
			assert not val


def test_unblock_client_request(  # pylint: disable=redefined-outer-name,unused-argument
	config: Config,
	test_client: OpsiconfdTestClient,
) -> None:
	with sync_redis_client() as redis:
		test_ip = "192.168.1.2"
		set_failed_auth_and_blocked(config, test_ip)
		res = test_client.post("/admin/unblock-client", auth=(ADMIN_USER, ADMIN_PASS), json={"client_addr": test_ip})
		assert res.status_code == 200

		val = redis.get(f"{config.redis_key('stats')}:client:blocked:{ip_address_to_redis_key(test_ip)}")
		assert not val


@pytest.mark.asyncio
async def test_unblock_client(config: Config, admininterface: ModuleType) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	with sync_redis_client() as redis:
		test_ip = "192.168.1.2"
		set_failed_auth_and_blocked(config, test_ip)

		headers = Headers()
		scope = {"method": "GET", "type": "http", "headers": headers}
		test_request = Request(scope=scope)
		test_request._json = {"client_addr": test_ip}  # pylint: disable=protected-access
		body = f'{{"client_addr":"{config.external_url}"}}'
		test_request._body = body.encode()  # pylint: disable=protected-access

		response = await admininterface.unblock_client(test_request)
		response_dict = json.loads(response.body)
		assert response.status_code == 200
		assert response_dict.get("error") is None

		val = redis.get(f"{config.redis_key('stats')}:client:blocked:{ip_address_to_redis_key(test_ip)}")
		assert not val


def test_unblock_client_exception(  # pylint: disable=redefined-outer-name,unused-argument
	config: Config,
	test_client: OpsiconfdTestClient,
) -> None:
	with sync_redis_client() as redis_client:
		test_ip = "192.168.1.2"
		set_failed_auth_and_blocked(config, test_ip)
		res = test_client.post("/admin/unblock-client", auth=(ADMIN_USER, ADMIN_PASS), json={"client_addr": None})
		assert res.status_code == 500

		val = redis_client.get(f"{config.redis_key('stats')}:client:blocked:{ip_address_to_redis_key(test_ip)}")
		assert val


def test_unblock_all_exception(  # pylint: disable=redefined-outer-name,unused-argument
	config: Config,
	test_client: OpsiconfdTestClient,
) -> None:
	addresses = ("10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888")
	for test_ip in addresses:
		set_failed_auth_and_blocked(config, test_ip)

	with patch("redis.asyncio.client.Redis.get", side_effect=Exception("ERROR")):
		res = test_client.post("/admin/unblock-all", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 500


@pytest.mark.asyncio
async def test_get_rpc_list_request(  # pylint: disable=redefined-outer-name,unused-argument
	config: Config,
	test_client: OpsiconfdTestClient,
) -> None:
	with patch("opsiconfd.application.jsonrpc.AWAIT_STORE_RPC_INFO", True):
		for _ in range(3):
			await run_in_threadpool(
				call_rpc,
				test_client,
				[{"id": 1, "method": "host_getIdents", "params": [None]}],
				[False],
			)
	response = await run_in_threadpool(test_client.get, "/admin/rpc-list", auth=(ADMIN_USER, ADMIN_PASS))
	assert response.status_code == 200
	result = response.json()
	for idx in range(3):
		assert result[idx].get("rpc_num") == 3 - idx
		assert result[idx].get("error") is False
		assert result[idx].get("params") == 1


def test_get_blocked_clients_request(  # pylint: disable=redefined-outer-name,unused-argument
	config: Config, test_client: OpsiconfdTestClient
) -> None:
	addresses = ("10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888")
	for test_ip in addresses:
		set_failed_auth_and_blocked(config, test_ip)

	res = test_client.get("/admin/blocked-clients", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	assert sorted(res.json()) == sorted(addresses)


@pytest.mark.asyncio
async def test_get_blocked_clients(  # pylint: disable=redefined-outer-name,unused-argument
	config: Config,
	admininterface: ModuleType,
) -> None:
	addresses = ("10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888")
	for test_ip in addresses:
		set_failed_auth_and_blocked(config, test_ip)

	result = await admininterface.get_blocked_clients()
	assert sorted(json.loads(result.body)) == sorted(addresses)


@pytest.mark.parametrize("num_rpcs", [1, 3, 5])
@pytest.mark.asyncio
async def test_get_rpc_list(  # pylint: disable=redefined-outer-name
	test_client: OpsiconfdTestClient, admininterface: ModuleType, num_rpcs: int
) -> None:
	with patch("opsiconfd.application.jsonrpc.AWAIT_STORE_RPC_INFO", True):
		for _ in range(num_rpcs):
			await run_in_threadpool(
				call_rpc,
				test_client,
				[{"id": 1, "method": "host_getIdents", "params": [None]}],
				[False],
			)

	rpc_list_response = await admininterface.get_rpc_list()
	rpc_list = json.loads(rpc_list_response.body)
	rpc_nums = []
	for rpc in rpc_list:
		rpc_nums.append(rpc.get("rpc_num"))
		assert rpc.get("error") is False
		assert rpc.get("params") == 1
	assert sorted(rpc_nums) == list(range(1, num_rpcs + 1))


@pytest.mark.asyncio
@pytest.mark.parametrize(
	"rpc_request_data, expected_response",
	[
		({"client_addr": "<local_ip>"}, [200, None, "<local_ip>", 1]),
		({"client_addr": "192.168.2.1"}, [200, None, "192.168.2.1", 0]),
		(None, [500, {"message": "client_addr missing"}, None, 1]),
	],
)  # pylint: disable=too-many-locals
async def test_delete_client_sessions(  # pylint: disable=redefined-outer-name,unused-argument,too-many-locals
	config: Config, admininterface: ModuleType, test_client: OpsiconfdTestClient, rpc_request_data: Any, expected_response: Any
) -> None:
	res = test_client.get("/admin/", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	with sync_redis_client() as redis:
		session = dict(res.cookies.items()).get("opsiconfd-session")  # type: ignore[no-untyped-call]
		sessions = []
		local_ip = None
		for key in redis.scan_iter(f"{config.redis_key('session')}:*"):
			addr, sess = key.decode("utf8").split(":")[-2:]
			sessions.append(sess)
			if sess == session:
				local_ip = addr

	rpc_request_data = json.loads(json.dumps(rpc_request_data).replace("<local_ip>", local_ip or ""))
	expected_response = json.loads(json.dumps(expected_response).replace("<local_ip>", local_ip or ""))

	assert session in sessions

	headers = Headers()
	scope = {"method": "GET", "type": "http", "headers": headers}
	test_request = Request(scope=scope)
	test_request._json = rpc_request_data  # pylint: disable=protected-access
	body = f"{rpc_request_data}"
	test_request._body = body.encode()  # pylint: disable=protected-access

	response = await admininterface.delete_client_sessions(test_request)

	response_dict = json.loads(response.body)
	assert response.status_code == expected_response[0]

	if expected_response[1]:
		assert response_dict.get("message", None) == expected_response[1].get("message")

	if response_dict.get("message") is None:
		assert response_dict.get("client") == expected_response[2]

	if response.status_code == 200 and response_dict.get("client") == local_ip:
		assert response_dict.get("sessions") == [session]
		assert len(response_dict.get("redis-keys")) == expected_response[3]


def test_open_grafana(test_client: OpsiconfdTestClient, config: Config) -> None:  # pylint: disable=redefined-outer-name
	async def create_dashboard_user() -> tuple[str, str]:
		return "", ""

	with patch("opsiconfd.application.admininterface.create_dashboard_user", create_dashboard_user):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)

		with get_config({"grafana_external_url": "https://grafana.test/"}):
			# External grafana server
			response = test_client.get(f"https://127.0.0.1:{config.port}/admin/grafana", follow_redirects=False)
			assert response.status_code == 307
			assert response.headers.get("location") == "https://grafana.test/d/opsiconfd_main/opsiconfd-main-dashboard?kiosk=tv"

		with get_config({"grafana_external_url": f"https://{FQDN}:3000"}):
			# Same server, different port
			response = test_client.get(f"https://{FQDN}:{config.port}/admin/grafana", follow_redirects=False)
			assert response.status_code == 307
			assert response.headers.get("location") == f"https://{FQDN}:3000/d/opsiconfd_main/opsiconfd-main-dashboard?kiosk=tv"

			# Same server, different port, request to different address (first redirect to fqdn)
			response = test_client.get(f"https://127.0.0.1:{config.port}/admin/grafana", follow_redirects=False)
			assert response.status_code == 307
			assert response.headers.get("location") == f"https://{FQDN}:{config.port}/admin/grafana"

		with get_config({"grafana_external_url": "/grafana-proxy"}):
			# opsiconfd as reverse proxy for grafana
			response = test_client.get(f"https://127.0.0.1:{config.port}/admin/grafana", follow_redirects=False)
			assert response.status_code == 307
			assert response.headers.get("location") == "/grafana-proxy/d/opsiconfd_main/opsiconfd-main-dashboard?kiosk=tv"


def test_get_num_servers(admininterface: ModuleType, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	assert admininterface.get_num_servers() == 1
	with depot_jsonrpc(test_client, "", "test-depot.uib.local"):
		assert admininterface.get_num_servers() == 2
	assert admininterface.get_num_servers() == 1


def test_get_num_clients(admininterface: ModuleType, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	assert admininterface.get_num_clients() == 0
	with (
		client_jsonrpc(test_client, "", "test-client1.uib.local"),
		client_jsonrpc(test_client, "", "test-client2.uib.local"),
		client_jsonrpc(test_client, "", "test-client3.uib.local"),
	):
		assert admininterface.get_num_clients() == 3
	assert admininterface.get_num_clients() == 0


@pytest.mark.asyncio
async def test_get_rpc_count(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	with patch("opsiconfd.application.jsonrpc.AWAIT_STORE_RPC_INFO", True):
		for _ in range(10):
			await run_in_threadpool(
				call_rpc,
				test_client,
				[{"id": 1, "method": "host_getIdents", "params": [None]}],
				[False],
			)
		res = await run_in_threadpool(test_client.get, "/admin/rpc-count", auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 200
		assert res.json() == {"rpc_count": 10}


def test_get_session_list(test_client: OpsiconfdTestClient, config: Config) -> None:  # pylint: disable=redefined-outer-name
	addr = test_client.get_client_address()
	res = test_client.get("/admin/session-list", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	body = res.json()
	assert len(body) == 1

	for idx in range(10):
		test_client.set_client_address("192.168.36." + str(idx), idx * 1000)
		call_rpc(test_client, [{"id": 1, "method": "host_getIdents", "params": [None]}], [False])

	test_client.set_client_address(addr[0], addr[1])
	res = test_client.get("/admin/session-list", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	body = res.json()
	assert len(body) == 12
	for _idx in range(2, 12):
		assert body[_idx].get("address") == "192.168.36." + str(_idx - 2)
		assert body[_idx].get("user_agent") == "testclient"
		assert body[_idx].get("max_age") == config.session_lifetime


def test_unlock_product(test_client: OpsiconfdTestClient, backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	test_products = [
		{"id": "test_product01", "name": "Test Product 01", "productVersion": "1.0", "packageVersion": "1", "priority": 80},
		{"id": "test_product02", "name": "Test Product 02", "productVersion": "1.0", "packageVersion": "1", "priority": 81},
		{"id": "test_product03", "name": "Test Product 03", "productVersion": "1.0", "packageVersion": "1", "priority": 70},
	]
	test_depots = ["test-depot.uib.local", "test2-depot.uib.local"]
	products = ["test_product01", "test_product02"]

	with (
		depot_jsonrpc(test_client, "", test_depots[0]),
		depot_jsonrpc(test_client, "", test_depots[1]),
		products_jsonrpc(test_client, "", test_products, test_depots),
	):
		locked_products = backend.getProductLocks_hash()
		# check that no products are locked
		assert locked_products == {}
		# lock 2 products and check that the proucts are locked
		for product in products:
			backend.lockProduct(product)
		locked_products = backend.getProductLocks_hash()
		assert locked_products == {products[0]: test_depots, products[1]: test_depots}
		# unlock product 1 on one depot and check that product 1 is unlocked on depot 1 and product 2 is still locked
		result = test_client.post(f"/admin/products/{products[0]}/unlock", auth=(ADMIN_USER, ADMIN_PASS), json={"depots": [test_depots[0]]})
		assert result.status_code == 200
		locked_products = backend.getProductLocks_hash()
		assert locked_products == {products[0]: [test_depots[1]], products[1]: test_depots}


def test_unlock_all_products(test_client: OpsiconfdTestClient, backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	test_products = [
		{"id": "test_product01", "name": "Test Product 01", "productVersion": "1.0", "packageVersion": "1", "priority": 80},
		{"id": "test_product02", "name": "Test Product 02", "productVersion": "1.0", "packageVersion": "1", "priority": 81},
		{"id": "test_product03", "name": "Test Product 03", "productVersion": "1.0", "packageVersion": "1", "priority": 70},
	]
	test_depots = ["test-depot.uib.local", "test2-depot.uib.local"]
	product = "test_product03"

	with (
		depot_jsonrpc(test_client, "", test_depots[0]),
		depot_jsonrpc(test_client, "", test_depots[1]),
		products_jsonrpc(test_client, "", test_products, test_depots),
	):
		# check that no products are locked
		locked_products = backend.getProductLocks_hash()
		assert locked_products == {}
		# lock product on all depots and check lock status
		backend.lockProduct(product)
		locked_products = backend.getProductLocks_hash()
		assert locked_products == {product: test_depots}
		# unlock all products on all depots and check that all products are unlocked
		result = test_client.post("/admin/products/unlock", auth=(ADMIN_USER, ADMIN_PASS))
		assert result.status_code == 200
		locked_products = backend.getProductLocks_hash()
		assert locked_products == {}


def test_get_locked_products_list(  # pylint: disable=redefined-outer-name
	test_client: OpsiconfdTestClient,
	backend: UnprotectedBackend,
) -> None:
	test_products = [
		{"id": "test_product01", "name": "Test Product 01", "productVersion": "1.0", "packageVersion": "1", "priority": 80},
		{"id": "test_product02", "name": "Test Product 02", "productVersion": "1.0", "packageVersion": "1", "priority": 81},
		{"id": "test_product03", "name": "Test Product 03", "productVersion": "1.0", "packageVersion": "1", "priority": 70},
	]
	test_depots = ["test-depot.uib.local", "test2-depot.uib.local"]
	products = ["test_product01", "test_product02"]

	with (
		depot_jsonrpc(test_client, "", test_depots[0]),
		depot_jsonrpc(test_client, "", test_depots[1]),
		products_jsonrpc(test_client, "", test_products, test_depots),
	):
		# lock products on depots
		for product in products:
			backend.lockProduct(product, test_depots)

		result = test_client.get("/admin/locked-products-list", auth=(ADMIN_USER, ADMIN_PASS))
		assert result.status_code == 200
		assert result.json() == {products[0]: test_depots, products[1]: test_depots}


def test_get_addon_list(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	response = test_client.get("/admin/addons", auth=(ADMIN_USER, ADMIN_PASS))
	assert response.status_code == 200
	print(response.json())
	addons = AddonManager().addons
	print(addons)
	assert len(response.json()) == len(addons)


def test_get_routes(  # pylint: disable=redefined-outer-name, unused-argument
	config: Config, test_client: OpsiconfdTestClient, cleanup: Callable
) -> None:
	# uses clean up from addon manager test (auto run is true)
	response = test_client.get("/admin/routes", auth=(ADMIN_USER, ADMIN_PASS))
	assert response.status_code == 200

	routes_to_test = {
		"/": "opsiconfd.application.main.index_head",
		"/admin/": "opsiconfd.application.admininterface.admin_interface_index",
		"/admin/addons": "opsiconfd.application.admininterface.get_addon_list",
		"/admin/addons/install": "opsiconfd.application.admininterface.install_addon",
		"/admin/blocked-clients": "opsiconfd.application.admininterface.get_blocked_clients",
		"/admin/config": "opsiconfd.application.admininterface.get_confd_conf",
		"/admin/delete-client-sessions": "opsiconfd.application.admininterface.delete_client_sessions",
		"/admin/grafana": "opsiconfd.application.admininterface.open_grafana",
		"/admin/locked-products-list": "opsiconfd.application.admininterface.get_locked_products_list",
		"/admin/products/unlock": "opsiconfd.application.admininterface.unlock_all_products",
		"/admin/products/{product}/unlock": "opsiconfd.application.admininterface.unlock_product",
		"/admin/reload": "opsiconfd.application.admininterface.reload",
		"/admin/routes": "opsiconfd.application.admininterface.get_routes",
		"/admin/rpc-count": "opsiconfd.application.admininterface.get_rpc_count",
		"/admin/rpc-list": "opsiconfd.application.admininterface.get_rpc_list",
		"/admin/session-list": "opsiconfd.application.admininterface.get_session_list",
		"/admin/unblock-all": "opsiconfd.application.admininterface.unblock_all_clients",
		"/admin/unblock-client": "opsiconfd.application.admininterface.unblock_client",
	}
	# test if default routes are in the list
	response_body = json.loads(response.content)
	print(response_body)
	for key in routes_to_test:
		assert key in response_body.keys()
		assert routes_to_test.get(key) == response_body.get(key)

	# load addon
	config.addon_dirs = [os.path.abspath("tests/data/addons")]
	os.path.join(tempfile.gettempdir(), "opsiconfd_test_addon", "test1_on_load")
	addon_manager = AddonManager()
	addon_manager.load_addons()

	response = test_client.get("/admin/routes", auth=(ADMIN_USER, ADMIN_PASS))
	assert response.status_code == 200

	addon_routes = {
		"/addons/test1": "opsiconfd.addon.test1.index",
		"/addons/test1/api/{any:path}": "opsiconfd.addon.test1.rest.route_get",
		"/addons/test1/login": "opsiconfd.addon.test1.login",
		"/addons/test1/logout": "opsiconfd.addon.test1.logout",
		"/addons/test1/public": "opsiconfd.addon.test1.public",
		"/addons/test1/static": "starlette.staticfiles",
	}

	# test if appon routes are in the list
	response_body = json.loads(response.content)
	for key in addon_routes:
		assert key in response_body.keys()
		assert addon_routes.get(key) == response_body.get(key)

	addon_manager.unload_addon("test1")


def test_licensing_info(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	response = test_client.get("/admin/licensing_info", auth=(ADMIN_USER, ADMIN_PASS))
	assert response.status_code == 200
	lic_data = response.json()
	print(response.json())
	assert isinstance(lic_data.get("info"), dict)
	assert lic_data.get("info").get("customer_name") is not None

	for clients in ("macos_clients", "linux_clients", "windows_clients", "all_clients"):
		assert isinstance(lic_data.get("info").get(clients), int)


def test_welcome_page(config: Config, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	res = test_client.get("/welcome", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	assert "<h1>Welcome to opsi!</h1>" in res.content.decode("utf8")
