# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test admininterface
"""

from socket import getfqdn
import sys
import json
import asyncio
import pytest
import aioredis

from fastapi import Response
from starlette.requests import Request
from starlette.datastructures import Headers

from opsiconfd.utils import ip_address_to_redis_key

from .utils import (  # pylint: disable=unused-import
	config,
	test_client,
	clean_redis,
	get_config,
	sync_redis_client,
	backend,
	client_jsonrpc,
	depot_jsonrpc,
	ADMIN_USER,
	ADMIN_PASS,
	OPSI_SESSION_KEY,
)


def set_failed_auth_and_blocked(ip_address):  # pylint: disable=redefined-outer-name
	with sync_redis_client() as redis:
		ip_address_redis = ip_address_to_redis_key(ip_address)
		redis.execute_command(
			f"ts.create opsiconfd:stats:client:failed_auth:{ip_address_redis} " f"RETENTION 86400000 LABELS client_addr {ip_address}"
		)
		redis.execute_command(
			f"ts.add opsiconfd:stats:client:failed_auth:{ip_address_redis} " f"* 11 RETENTION 86400000 LABELS client_addr {ip_address}"
		)
		redis.set(f"opsiconfd:stats:client:blocked:{ip_address_redis}", 1)


def call_rpc(client, rpc_request_data: list, expect_error: list):
	for idx, data in enumerate(rpc_request_data):
		result = client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=data)
		result_json = json.loads(result.text)
		assert result.status_code == 200
		if expect_error[idx]:
			assert result_json.get("result") is None
		else:
			assert result_json.get("result") is not None
			assert result_json.get("error") is None


@pytest.fixture(name="admininterface")
def fixture_admininterface(monkeypatch):
	monkeypatch.setattr(sys, "argv", ["opsiconfd"])
	from opsiconfd.application import admininterface  # pylint: disable=import-outside-toplevel, redefined-outer-name

	return admininterface


@pytest.mark.asyncio
async def test_unblock_all_request(test_client, config):  # pylint: disable=redefined-outer-name,unused-argument
	redis_client = aioredis.StrictRedis.from_url(config.redis_internal_url)
	addresses = ["10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888"]
	for test_ip in addresses:
		set_failed_auth_and_blocked(test_ip)

	res = test_client.post("/admin/unblock-all", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200

	for test_ip in addresses:
		val = await redis_client.get(f"opsiconfd:stats:client:blocked:{ip_address_to_redis_key(test_ip)}")
		assert not val


@pytest.mark.asyncio
async def test_unblock_all(config, admininterface):  # pylint: disable=redefined-outer-name,unused-argument
	redis_client = aioredis.StrictRedis.from_url(config.redis_internal_url)
	test_response = Response()
	addresses = ["10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888"]

	for test_ip in addresses:
		set_failed_auth_and_blocked(test_ip)

	response = await admininterface.unblock_all_clients(test_response)

	assert response.status_code == 200
	response_body = json.loads(response.body)
	assert response_body.get("error") is None
	assert response_body.get("status") == 200
	assert sorted(response_body["data"]["clients"]) == sorted(addresses)

	for test_ip in addresses:
		val = await redis_client.get(f"opsiconfd:stats:client:blocked:{ip_address_to_redis_key(test_ip)}")
		assert not val


@pytest.mark.asyncio
async def test_unblock_client_request(config, test_client):  # pylint: disable=redefined-outer-name,unused-argument
	redis_client = aioredis.StrictRedis.from_url(config.redis_internal_url)
	test_ip = "192.168.1.2"
	set_failed_auth_and_blocked(test_ip)
	res = test_client.post("/admin/unblock-client", auth=(ADMIN_USER, ADMIN_PASS), json={"client_addr": test_ip})
	assert res.status_code == 200

	val = await redis_client.get(f"opsiconfd:stats:client:blocked:{ip_address_to_redis_key(test_ip)}")
	assert not val


@pytest.mark.asyncio
async def test_unblock_client(config, admininterface):  # pylint: disable=redefined-outer-name,unused-argument
	redis_client = aioredis.StrictRedis.from_url(config.redis_internal_url)
	test_ip = "192.168.1.2"
	set_failed_auth_and_blocked(test_ip)

	headers = Headers()
	scope = {"method": "GET", "type": "http", "headers": headers}
	test_request = Request(scope=scope)
	test_request._json = {"client_addr": test_ip}  # pylint: disable=protected-access
	body = f'{{"client_addr":"{config.external_url}"}}'
	test_request._body = body.encode()  # pylint: disable=protected-access

	response = await admininterface.unblock_client(test_request)
	response_dict = json.loads(response.body)
	assert response_dict.get("status") == 200
	assert response_dict.get("error") is None

	val = await redis_client.get(f"opsiconfd:stats:client:blocked:{ip_address_to_redis_key(test_ip)}")
	assert not val


def test_get_rpc_list_request(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	for _idx in range(3):
		call_rpc(test_client, [{"id": 1, "method": "host_getIdents", "params": [None]}], [False])

	response = test_client.get("/admin/rpc-list", auth=(ADMIN_USER, ADMIN_PASS))
	assert response.status_code == 200
	result = response.json()
	for idx in range(3):
		assert result[idx].get("rpc_num") == idx + 1
		assert result[idx].get("error") is False
		assert result[idx].get("params") == 1


@pytest.mark.asyncio
async def test_get_blocked_clients_request(config, test_client):  # pylint: disable=redefined-outer-name,unused-argument
	addresses = ["10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888"]
	for test_ip in addresses:
		set_failed_auth_and_blocked(test_ip)

	res = test_client.get("/admin/blocked-clients", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200
	assert sorted(res.json()) == sorted(addresses)


@pytest.mark.asyncio
async def test_get_blocked_clients(admininterface):  # pylint: disable=redefined-outer-name,unused-argument
	addresses = ["10.10.1.1", "192.168.1.2", "2001:4860:4860:0000:0000:0000:0000:8888"]
	for test_ip in addresses:
		set_failed_auth_and_blocked(test_ip)

	blocked_clients = await admininterface.get_blocked_clients()
	assert sorted(blocked_clients) == sorted(addresses)


@pytest.mark.parametrize("num_rpcs", [1, 3, 5])
@pytest.mark.asyncio
async def test_get_rpc_list(test_client, admininterface, num_rpcs):  # pylint: disable=redefined-outer-name

	for _idx in range(num_rpcs):
		call_rpc(test_client, [{"id": 1, "method": "host_getIdents", "params": [None]}], [False])

	await asyncio.sleep(1)

	rpc_list = await admininterface.get_rpc_list()
	for idx in range(0, num_rpcs):
		assert rpc_list[idx].get("rpc_num") == idx + 1
		assert rpc_list[idx].get("error") is False
		assert rpc_list[idx].get("params") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
	"rpc_request_data, expected_response",
	[
		({"client_addr": "<local_ip>"}, [200, None, "<local_ip>", 1]),
		({"client_addr": "192.168.2.1"}, [200, None, "192.168.2.1", 0]),
		(None, [500, {"detail": "client_addr missing", "message": "Error while removing redis client keys"}, None, 1]),
	],
)  # pylint: disable=too-many-locals
async def test_delete_client_sessions(
	config, admininterface, test_client, rpc_request_data, expected_response
):  # pylint: disable=redefined-outer-name,unused-argument,too-many-locals
	res = test_client.get("/admin/", auth=(ADMIN_USER, ADMIN_PASS), verify=False)
	assert res.status_code == 200
	redis_client = aioredis.StrictRedis.from_url(config.redis_internal_url)

	session = res.cookies.get_dict().get("opsiconfd-session")
	sessions = []
	local_ip = None
	async for key in redis_client.scan_iter(f"{OPSI_SESSION_KEY}:*"):
		addr, sess = key.decode("utf8").split(":")[-2:]
		sessions.append(sess)
		if sess == session:
			local_ip = addr

	rpc_request_data = json.loads(json.dumps(rpc_request_data).replace("<local_ip>", local_ip))
	expected_response = json.loads(json.dumps(expected_response).replace("<local_ip>", local_ip))

	assert session in sessions

	headers = Headers()
	scope = {"method": "GET", "type": "http", "headers": headers}
	test_request = Request(scope=scope)
	test_request._json = rpc_request_data  # pylint: disable=protected-access
	body = f"{rpc_request_data}"
	test_request._body = body.encode()  # pylint: disable=protected-access

	response = await admininterface.delete_client_sessions(test_request)

	response_dict = json.loads(response.body)
	assert response_dict.get("status") == expected_response[0]
	assert response_dict.get("error") == expected_response[1]

	if response_dict.get("error") is None:
		assert response_dict.get("data").get("client") == expected_response[2]

	if response_dict.get("status") == 200 and response_dict.get("data").get("client") == local_ip:
		assert response_dict.get("data").get("sessions") == [session]
		assert len(response_dict.get("data").get("redis-keys")) == expected_response[3]


def test_open_grafana(test_client, config):  # pylint: disable=redefined-outer-name
	response = test_client.get("/admin/grafana", auth=(ADMIN_USER, ADMIN_PASS), allow_redirects=False)
	assert response.status_code == 308
	assert response.headers.get("location") == f"https://{getfqdn()}:{config.port}/admin/grafana"

	test_client.set_client_address("192.168.1.1", "4447")
	response = test_client.get("/admin/grafana", auth=(ADMIN_USER, ADMIN_PASS), allow_redirects=False)


def test_get_num_servers(admininterface, backend, test_client):  # pylint: disable=redefined-outer-name
	assert admininterface.get_num_servers(backend) == 1
	with depot_jsonrpc(test_client, "", "test-depot.uib.local"):
		assert admininterface.get_num_servers(backend) == 2
	assert admininterface.get_num_servers(backend) == 1


def test_get_num_clients(admininterface, backend, test_client):  # pylint: disable=redefined-outer-name
	assert admininterface.get_num_clients(backend) == 0

	with (
		client_jsonrpc(test_client, "", "test-client1.uib.local"),
		client_jsonrpc(test_client, "", "test-client2.uib.local"),
		client_jsonrpc(test_client, "", "test-client3.uib.local"),
	):
		assert admininterface.get_num_clients(backend) == 3
	assert admininterface.get_num_clients(backend) == 0
