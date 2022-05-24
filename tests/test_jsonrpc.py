# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
jsonrpc tests
"""

import json
from unittest.mock import patch

import msgpack  # type: ignore[import]
import pytest
from opsicommon.objects import OpsiClient  # type: ignore[import]

from opsiconfd.application.jsonrpc import (
	compress_data,
	decompress_data,
	deserialize_data,
	get_sort_algorithm,
	serialize_data,
)

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	backend,
	clean_redis,
	config,
	get_config,
	get_dummy_products,
	products_jsonrpc,
	sync_redis_client,
	test_client,
)


def test_request(test_client):  # pylint: disable=redefined-outer-name
	client_data = {
		"id": "test-jsonrpc-request.opsi.org",
		"description": "description",
		"notes": "notes",
		"hardwareAddress": "08:00:22:aa:66:ee",
		"ipAddress": "192.168.10.188",
		"inventoryNumber": "I01012393278",
	}
	client = OpsiClient(**client_data)

	rpc = {"id": 12345, "method": "host_createObjects", "params": [client.to_hash()]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	result = res.json()
	assert result["id"] == rpc["id"]
	assert result["error"] is None
	assert result["result"] == []

	rpc = {"id": 12346, "method": "host_getObjects", "params": [[], {"id": client.id}]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	result = res.json()
	assert result["id"] == rpc["id"]
	assert result["error"] is None
	for attr, val in client_data.items():
		assert result["result"][0].get(attr) == val


def test_multi_request(test_client):  # pylint: disable=redefined-outer-name
	client1 = OpsiClient(id="test-jsonrpc-request-multi-1.opsi.org")
	client2 = OpsiClient(id="test-jsonrpc-request-multi-2.opsi.org")
	rpc = (
		{"id": 1, "method": "host_createObjects", "params": [client1.to_hash()]},
		{"id": 2, "method": "host_createObjects", "params": [client2.to_hash()]},
	)
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	result = res.json()
	assert len(result) == 2
	for res in result:
		assert res["id"] in (rpc[0]["id"], rpc[1]["id"])  # pylint: disable=loop-invariant-statement
		assert res["error"] is None
		assert res["result"] == []


def test_incomplete_request(test_client):  # pylint: disable=redefined-outer-name
	rpcs = (
		{"id": 0, "method": "backend_getInterface"},
		{"method": "backend_getInterface"},
	)
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpcs)
	res.raise_for_status()
	response = res.json()
	assert len(response) == 2
	for result in response:
		assert result["id"] == 0
		assert result["result"]
		assert result["error"] is None


def test_jsonrpc20(test_client):  # pylint: disable=redefined-outer-name
	rpcs = (
		{"id": 1, "method": "backend_getInterface", "params": []},
		{"id": 2, "method": "backend_getInterface", "params": [], "jsonrpc": "1.0"},
		{"id": 3, "method": "backend_getInterface", "params": [], "jsonrpc": "2.0"},
	)
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpcs)
	res.raise_for_status()
	response = res.json()
	assert len(response) == 3
	for result in response:
		assert result["id"] in (1, 2, 3)
		assert result["result"]
		if result["id"] in (1, 2):
			assert "jsonrpc" not in result
			assert result["error"] is None
		else:
			assert result["jsonrpc"] == "2.0"
			assert "error" not in result


@pytest.mark.parametrize(
	"content_type, accept, expected_content_type",
	(
		("application/json", None, "application/json"),
		("json", None, "application/json"),
		("", None, "application/json"),
		(None, None, "application/json"),
		("xyasdb;dsaoswe3dod", None, "application/json"),
		("application/msgpack", None, "application/msgpack"),
		("msgpack", None, "application/msgpack"),
		("application/msgpack", "application/json", "application/msgpack"),  # Content-Type should be preferred
		(None, None, "application/json"),
		("", "", "application/json"),
		("", "msgpack", "application/msgpack"),
		("msgpack", "xyasdb;dsaoswe3dod", "application/msgpack"),
		("invalid", "application/msgpack", "application/msgpack"),

	),
)
def test_serializations(test_client, content_type, accept, expected_content_type):  # pylint: disable=redefined-outer-name
	products = get_dummy_products(3)
	product_ids = [p["id"] for p in products]
	with products_jsonrpc(test_client, "", products):  # Create products
		rpc = {"id": "serialization", "method": "product_getObjects", "params": [[], {"id": product_ids}]}
		headers = {}
		if content_type is not None:
			headers["Content-Type"] = content_type
		if accept is not None:
			headers["Accept"] = accept
		serialization = (content_type or "").split("/")[-1]
		if serialization not in ("json", "msgpack"):
			serialization = "json"
		res = test_client.post(
			"/rpc",
			auth=(ADMIN_USER, ADMIN_PASS),
			data=serialize_data(rpc, serialization),
			headers=headers,
			stream=True,
		)
		res.raise_for_status()
		assert res.headers["Content-Type"] == expected_content_type
		assert deserialize_data(res.raw.read(), expected_content_type.split("/")[-1])


@pytest.mark.parametrize(
	"content_encoding, accept_encoding, status_code",
	(
		("deflate", "deflate", 200),
		("gzip", "gzip", 200),
		("lz4", "lz4", 200),
		("invalid", "lz4", 400),
		("lz4", "invalid", 400),
	),
)
def test_compression(test_client, content_encoding, accept_encoding, status_code):  # pylint: disable=redefined-outer-name
	products = get_dummy_products(3)
	product_ids = [p["id"] for p in products]
	with (products_jsonrpc(test_client, "", products), patch("opsiconfd.application.jsonrpc.COMPRESS_MIN_SIZE", 0)):
		rpc = {"id": "compression", "method": "product_getObjects", "params": [[], {"id": product_ids}]}
		data = serialize_data(rpc, "json")
		if accept_encoding != "invalid":
			data = compress_data(data, accept_encoding)
		res = test_client.post(
			"/rpc",
			auth=(ADMIN_USER, ADMIN_PASS),
			data=data,
			headers={"Content-Type": "application/json", "Content-Encoding": content_encoding, "Accept-Encoding": accept_encoding},
			stream=True,
		)
		assert res.status_code == status_code
		if accept_encoding == "invalid":
			assert res.headers.get("Content-Encoding") is None
		else:
			assert res.headers.get("Content-Encoding") == accept_encoding
		data = res.raw.read()
		# gzip and deflate transfer-encodings are automatically decoded
		if "lz4" in accept_encoding:
			data = decompress_data(data, accept_encoding)
		assert deserialize_data(data, "json")


def test_error_log(test_client, tmp_path):  # pylint: disable=redefined-outer-name
	with (patch("opsiconfd.application.jsonrpc.RPC_DEBUG_DIR", str(tmp_path)), get_config({"debug_options": "rpc-error-log"})):
		rpc = {"id": 1, "method": "invalid", "params": [1, 2, 3]}
		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
		res.raise_for_status()
		for entry in tmp_path.iterdir():
			data = json.loads(entry.read_text(encoding="utf-8"))  # pylint: disable=dotted-import-in-loop
			assert data["client"]
			assert "Processing request from" in data["description"]
			assert data["method"] == "invalid"
			assert data["params"] == [1, 2, 3]
			assert data["error"] == "Invalid method 'invalid'"


def test_store_rpc_info(test_client):  # pylint: disable=redefined-outer-name
	with sync_redis_client() as redis:
		for num in (1, 2):
			rpc = {"id": num, "method": "host_getObjects", "params": [["id"], {"type": "OpsiDepotserver"}]}  # pylint: disable=loop-invariant-statement
			res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
			res.raise_for_status()
			result = res.json()
			num_results = len(result["result"])
			assert num_results > 0
			if num == 2:
				assert int(redis.get("opsiconfd:stats:num_rpcs")) == 2
				redis_result = redis.lrange("opsiconfd:stats:rpcs", 0, -1)
				infos = [msgpack.loads(value) for value in redis_result]  # pylint: disable=dotted-import-in-loop
				assert len(infos) == 2
				for info in infos:
					assert info["rpc_num"] in (1, 2)
					assert info["duration"] > 0
					assert info["date"]
					assert info["client"]
					assert info["error"] is False
					assert info["num_results"] == num_results
					assert info["num_params"] == 2


@pytest.mark.asyncio
async def test_get_sort_algorithm(backend):  # pylint: disable=redefined-outer-name
	assert await get_sort_algorithm("algorithm1") == "algorithm1"
	assert await get_sort_algorithm("algorithm2") == "algorithm2"
	backend.config_create(
		id="product_sort_algorithm",
		description="Product sorting algorithm",
		possibleValues=["algorithm1", "algorithm2"],
		defaultValues=["algorithm2"],
		editable=False,
		multiValue=False,
	)
	assert await get_sort_algorithm("invalid") == "algorithm2"
	backend.config_create(
		id="product_sort_algorithm",
		description="Product sorting algorithm",
		possibleValues=["algorithm1", "algorithm2"],
		defaultValues=["algorithm1"],
		editable=False,
		multiValue=False,
	)
	assert await get_sort_algorithm() == "algorithm1"
