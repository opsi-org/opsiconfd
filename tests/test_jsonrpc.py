# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
jsonrpc tests
"""

import json
import shutil
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal
from unittest.mock import patch

import msgpack
import msgspec
import pytest
from opsi.compression import compress, decompress
from opsi.opsi.service.model.object import ConfigState, LocalbootProduct, OpsiClient, ProductOnClient, serialize

from opsiconfd.application.jsonrpc import (
	SMALL_DATA_MAX_ITEMS,
	SMALL_DATA_MAX_STR_LEN,
	JSONRPC20Error,
	JSONRPC20ErrorResponse,
	JSONRPC20Request,
	JSONRPCRequest,
	JSONRPCResponse,
	RequestInfo,
	deserialize_data,
	deserialize_params,
	is_small_data,
	serialize_data,
	serialize_result,
	store_rpc_info,
)
from opsiconfd.backend.rpc import get_method_interface
from opsiconfd.redis import redis_client

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	backend,
	clean_mysql,
	clean_redis,
	config,
	get_config,
	get_dummy_products,
	products_jsonrpc,
	test_client,
)

TESTDIR = Path("tests/data/jsonrpc/test_dir")
TESTFILE = TESTDIR / "testfile"
TESTPACKAGE_NAME = "localboot_legacy"
TESTPACKAGE = Path(f"tests/data/jsonrpc/{TESTPACKAGE_NAME}_42.0-1337.opsi")
CONTROLFILE = Path("tests/data/jsonrpc/control")


def _get_objects(self: object, attributes: list[str] | None = None, **filter: Any) -> None:
	pass


def test_deserialize_params() -> None:
	method_interface = get_method_interface(_get_objects)
	client = OpsiClient(id="client1.opsi.test")

	# Positional params with keyword arguments dict as last param
	params = [["id"], {"id": "client1.opsi.test", "host": client.to_hash()}]
	args, keywords = deserialize_params(params, method_interface)
	assert args == [["id"]]
	assert keywords["id"] == "client1.opsi.test"
	assert isinstance(keywords["host"], OpsiClient)
	# Original params must not be modified
	assert len(params) == 2

	# Positional params without keyword arguments
	args, keywords = deserialize_params([[client.to_hash()]], method_interface)
	assert isinstance(args[0][0], OpsiClient)
	assert keywords == {}

	# Named params
	args, keywords = deserialize_params({"attributes": ["id"], "id": "client1.opsi.test"}, method_interface)
	assert args == []
	assert keywords == {"attributes": ["id"], "id": "client1.opsi.test"}

	with pytest.raises(TypeError, match="kwargs param is not a dict"):
		deserialize_params([["id"], "invalid"], method_interface)


@pytest.mark.parametrize(
	"data, expected",
	(
		(None, True),
		(1, True),
		("x" * SMALL_DATA_MAX_STR_LEN, True),
		("x" * (SMALL_DATA_MAX_STR_LEN + 1), False),
		([{"id": "client1.opsi.test", "type": "OpsiClient"}], True),
		(list(range(SMALL_DATA_MAX_ITEMS)), True),
		(list(range(SMALL_DATA_MAX_ITEMS + 1)), False),
		({"a": [{"b": list(range(SMALL_DATA_MAX_ITEMS))}]}, False),
		([["x" * (SMALL_DATA_MAX_STR_LEN // 2)], ["x" * (SMALL_DATA_MAX_STR_LEN // 2 + 1)]], False),
		([OpsiClient(id="client1.opsi.test")], False),
	),
)
def test_is_small_data(data: Any, expected: bool) -> None:
	assert is_small_data(data) is expected


class CustomSerializeProductOnClient(ProductOnClient):
	def serialize(self) -> dict[str, Any]:
		return {"custom": self.productId}


def _get_serialize_test_objects() -> list[Any]:
	client = OpsiClient(id="client1.opsi.test", description="test")
	client.created = datetime(2026, 1, 2, 3, 4, 5)  # ty: ignore[invalid-assignment]
	client.lastSeen = date(2026, 1, 2)  # ty: ignore[invalid-assignment]
	poc = ProductOnClient(
		productId="product1", productType="LocalbootProduct", clientId="client1.opsi.test", modificationTime="2026-01-01 00:00:00"
	)
	poc_int_ident = ProductOnClient(productId="product2", productType="LocalbootProduct", clientId="client1.opsi.test")
	poc_int_ident.productId = 1  # ty: ignore[invalid-assignment]
	poc_int_ident.clientId = None  # ty: ignore[invalid-assignment]
	poc_generated_default = ProductOnClient(productId="product3", productType="LocalbootProduct", clientId="client1.opsi.test")
	poc_generated_default.setGeneratedDefault(True)
	return [
		client,
		poc,
		poc_int_ident,
		poc_generated_default,
		LocalbootProduct(id="product1", productVersion="1.0", packageVersion="1"),
		ConfigState(configId="config1", objectId="client1.opsi.test", values=["a", "b"]),
		CustomSerializeProductOnClient(productId="product4", productType="LocalbootProduct", clientId="client1.opsi.test"),
	]


@pytest.mark.parametrize(
	"data_factory",
	(
		lambda: None,
		lambda: "string",
		lambda: {"key": OpsiClient(id="client1.opsi.test")},
		list,
		_get_serialize_test_objects,
		lambda: _get_serialize_test_objects()[0],
		lambda: [_get_serialize_test_objects(), [{"id": "x"}, 1]],
		lambda: {OpsiClient(id="client1.opsi.test")},
		lambda: (obj for obj in _get_serialize_test_objects()),
	),
)
def test_serialize_result(data_factory: Any) -> None:
	result = serialize_result(data_factory())
	expected = serialize(data_factory())
	assert result == expected
	# Key order must also be identical
	assert json.dumps(result, default=str) == json.dumps(expected, default=str)


def test_request_param_list(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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
	assert result["result"] is None

	rpc = {"id": 12346, "method": "host_getObjects", "params": [[], {"id": client.id}]}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	result = res.json()
	assert result["id"] == rpc["id"]
	assert result["error"] is None
	for attr, val in client_data.items():
		assert result["result"][0].get(attr) == val


def test_request_param_dict(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	client_data = {
		"id": "test-jsonrpc-request.opsi.org",
		"description": "description",
		"notes": "notes",
		"hardwareAddress": "08:00:22:aa:66:ee",
		"ipAddress": "192.168.10.188",
		"inventoryNumber": "I01012393278",
	}
	client = OpsiClient(**client_data)

	rpc = {"id": 12345, "method": "host_createOpsiClient", "params": client_data}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	result = res.json()
	assert result["id"] == rpc["id"]
	assert result["error"] is None
	assert result["result"] is None

	rpc = {"id": 12346, "method": "host_getObjects", "params": {"id": client.id}}
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	res.raise_for_status()
	result = res.json()
	assert result["id"] == rpc["id"]
	assert result["error"] is None
	for attr, val in client_data.items():
		assert result["result"][0].get(attr) == val


def test_multi_request(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	client1 = OpsiClient(id="test-jsonrpc-request-multi-1.opsi.org")
	client2 = OpsiClient(id="test-jsonrpc-request-multi-2.opsi.org")
	rpc = (
		{"id": 1, "method": "host_createObjects", "params": [client1.to_hash()]},
		{"id": 2, "method": "host_createObjects", "params": [client2.to_hash()]},
	)
	resp = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
	resp.raise_for_status()
	result = resp.json()
	assert len(result) == 2
	for res in result:
		assert res["id"] in (rpc[0]["id"], rpc[1]["id"])
		assert res["error"] is None
		assert res["result"] is None


def test_incomplete_request(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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


def test_jsonrpc20(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	rpcs = (
		{"id": 1, "method": "backend_getInterface", "params": []},
		{"id": 2, "method": "backend_getInterface", "params": [], "jsonrpc": "1.0"},
		{"id": 3, "method": "invalid", "params": []},
		{"id": 4, "method": "backend_getInterface", "params": [], "jsonrpc": "2.0"},
		{"id": 5, "method": "invalid", "params": [], "jsonrpc": "2.0"},
	)
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpcs)
	res.raise_for_status()
	response = res.json()
	assert len(response) == 5
	for result in response:
		assert result["id"] in (1, 2, 3, 4, 5)
		if result["id"] in (1, 2):
			assert "jsonrpc" not in result
			assert result["result"] is not None
			assert result["error"] is None
		elif result["id"] == 3:
			assert "jsonrpc" not in result
			assert result["result"] is None
			assert result["error"]["message"] == "Invalid method 'invalid'"
			assert result["error"]["class"] == "ValueError"
			assert "Traceback" in result["error"]["details"]
		elif result["id"] == 4:
			assert result["jsonrpc"] == "2.0"
			assert result["result"] is not None
			assert "error" not in result
		elif result["id"] == 5:
			assert result["jsonrpc"] == "2.0"
			assert result["error"]["code"] == 0
			assert result["error"]["message"] == "Invalid method 'invalid'"
			assert result["error"]["data"]["class"] == "ValueError"
			assert "Traceback" in result["error"]["data"]["details"]


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
		("", "", "application/json"),
		("", "msgpack", "application/msgpack"),
		("msgpack", "xyasdb;dsaoswe3dod", "application/msgpack"),
		("invalid", "application/msgpack", "application/msgpack"),
	),
)
def test_serializations(
	test_client: OpsiconfdTestClient,  # noqa: F811
	content_type: str,
	accept: str,
	expected_content_type: str,
) -> None:
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
		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), content=serialize_data(rpc, serialization), headers=headers)
		res.raise_for_status()
		assert res.headers["Content-Type"] == expected_content_type
		assert deserialize_data(res.content, expected_content_type.split("/")[-1])


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
def test_compression(
	test_client: OpsiconfdTestClient,  # noqa: F811
	content_encoding: str,
	accept_encoding: Literal["deflate", "gzip", "lz4"],
	status_code: int,
) -> None:
	products = get_dummy_products(3)
	product_ids = [p["id"] for p in products]
	with products_jsonrpc(test_client, "", products), patch("opsiconfd.application.jsonrpc.COMPRESS_MIN_SIZE", 0):
		rpc = {"id": "compression", "method": "product_getObjects", "params": [[], {"id": product_ids}]}
		data = serialize_data(rpc, "json")
		if accept_encoding != "invalid":
			data = compress(data, accept_encoding)
		res = test_client.post(
			"/rpc",
			auth=(ADMIN_USER, ADMIN_PASS),
			content=data,
			headers={"Content-Type": "application/json", "Content-Encoding": content_encoding, "Accept-Encoding": accept_encoding},
		)
		assert res.status_code == status_code
		if accept_encoding == "invalid":
			assert res.headers.get("Content-Encoding") is None
		else:
			assert res.headers.get("Content-Encoding") == accept_encoding
		data = res.content
		# gzip and deflate transfer-encodings are automatically decoded
		if "lz4" in accept_encoding:
			data = decompress(data, accept_encoding)
		assert deserialize_data(data, "json")


def test_error_log(test_client: OpsiconfdTestClient, tmp_path: Path) -> None:  # noqa: F811
	with patch("opsiconfd.application.jsonrpc.RPC_DEBUG_DIR", str(tmp_path)), get_config({"debug_options": "rpc-error-log"}):
		rpc = {"id": 1, "method": "invalid", "params": [1, 2, 3]}
		res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
		res.raise_for_status()
		for entry in tmp_path.iterdir():
			data = json.loads(entry.read_text(encoding="utf-8"))
			assert data["client"]
			assert "Processing request from" in data["description"]
			assert data["request"]["method"] == "invalid"
			assert data["request"]["params"] == [1, 2, 3]
			assert data["response"]["error"]["message"] == "Invalid method 'invalid'"
			assert data["error"] == "Invalid method 'invalid'"


def test_store_rpc_info(config: Config, test_client: OpsiconfdTestClient) -> None:  # noqa: F811  # noqa: F811
	with patch("opsiconfd.application.jsonrpc.AWAIT_STORE_RPC_INFO", True):
		for num in (1, 2):
			rpc = {
				"id": num,
				"method": "host_getObjects",
				"params": [["id"], {"type": "OpsiDepotserver"}],
			}
			res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpc)
			res.raise_for_status()
			result = res.json()
			num_results = len(result["result"])
			assert num_results > 0
			if num == 2:
				redis = redis_client()
				assert int(redis.get(f"{config.redis_key('stats')}:num_rpcs") or 0) == 2
				redis_result = redis.lrange(f"{config.redis_key('stats')}:rpcs", 0, -1)
				infos = [msgpack.loads(value) for value in redis_result]
				assert len(infos) == 2
				for info in infos:
					assert info["rpc_num"] in (1, 2)
					assert info["duration"] > 0
					assert info["date"]
					assert info["client"]
					assert info["error"] is False
					assert info["num_results"] == num_results
					assert info["num_params"] == 2


@pytest.mark.parametrize(
	"start_num",
	(0, 126, 127, 254, 255, 65534, 65535, 2**32 - 1, 2**40),
)
async def test_store_rpc_info_rpc_num(config: Config, start_num: int) -> None:  # noqa: F811
	redis = redis_client()
	redis_prefix_stats = config.redis_key("stats")
	redis.set(f"{redis_prefix_stats}:num_rpcs", start_num)

	request_info = RequestInfo(client="127.0.0.1/test", duration=0.5)
	requests_responses: list[tuple[Any, Any]] = [
		(
			JSONRPC20Request(id=1, method="host_getObjects", params=[["id"], {"type": "OpsiClient"}], info=request_info),
			JSONRPCResponse(id=1, result=[1, 2, 3]),
		),
		(
			JSONRPCRequest(id=2, method="invalid", info=request_info),
			JSONRPC20ErrorResponse(id=2, error=JSONRPC20Error(message="error")),
		),
	]
	for request, response in requests_responses:
		await store_rpc_info(request, response)

	assert int(redis.get(f"{redis_prefix_stats}:num_rpcs") or 0) == start_num + 2
	redis_result = list(reversed(redis.lrange(f"{redis_prefix_stats}:rpcs", 0, -1)))
	assert len(redis_result) == 2
	for idx, value in enumerate(redis_result):
		info = msgspec.msgpack.decode(value)
		expected = {
			"rpc_num": start_num + idx + 1,
			"method": requests_responses[idx][0].method,
			"deprecated": False,
			"num_params": 2 if idx == 0 else 0,
			"date": request_info.date.strftime("%Y-%m-%dT%H:%M:%SZ"),
			"client": "127.0.0.1/test",
			"error": idx == 1,
			"num_results": 3 if idx == 0 else 0,
			"duration": 0.5,
			"worker": info["worker"],
		}
		assert info == expected
		# Must be identical to the msgpack encoding of msgspec
		assert value == msgspec.msgpack.encode(expected)


def test_jsonrpc_depotservermixin(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	rpcs = (
		# {"id": 1, "method": "depot_getHostRSAPublicKey", "params": []},  # No such file or directory: '/etc/ssh/ssh_host_rsa_key.pub'
		{"id": 2, "method": "depot_getMD5Sum", "params": [str(TESTFILE)]},
		{"id": 3, "method": "depot_getDiskSpaceUsage", "params": [str(TESTDIR)]},
	)
	res = test_client.post("/rpc", auth=(ADMIN_USER, ADMIN_PASS), json=rpcs)
	res.raise_for_status()
	response = res.json()
	assert len(response) == 2
	for result in response:
		if result["id"] == 1:
			print(result)
			assert False
		elif result["id"] == 2:
			assert result["result"] == "d8e8fca2dc0f896fd7cb4cb0031ba249"
		elif result["id"] == 3:
			assert result["result"]["available"] and result["result"]["capacity"] and result["result"]["usage"] and result["result"]["used"]
		else:
			raise ValueError(f"Received response with unexpected id {result['id']}")


def test_jsonrpc_package_install(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.post(
		"/rpc", auth=(ADMIN_USER, ADMIN_PASS), json={"id": 1, "method": "depot_installPackage", "params": [str(TESTPACKAGE)]}
	)
	res.raise_for_status()
	response = res.json()
	assert not response["error"]
	assert Path(f"/var/lib/opsi/depot/{TESTPACKAGE_NAME}").exists()
	assert Path("/tmp/bar").exists()
	assert Path("/tmp/foo/baz").exists()
	Path(f"/var/lib/opsi/depot/{TESTPACKAGE_NAME}/{TESTPACKAGE_NAME}.files").unlink()
	res = test_client.post(
		"/rpc", auth=(ADMIN_USER, ADMIN_PASS), json={"id": 2, "method": "depot_createPackageContentFile", "params": [TESTPACKAGE_NAME]}
	)
	res.raise_for_status()
	response = res.json()
	print(response)
	assert not response["error"]
	assert Path(f"/var/lib/opsi/depot/{TESTPACKAGE_NAME}/{TESTPACKAGE_NAME}.files").exists()
	res = test_client.post(
		"/rpc", auth=(ADMIN_USER, ADMIN_PASS), json={"id": 3, "method": "depot_uninstallPackage", "params": [TESTPACKAGE_NAME]}
	)
	res.raise_for_status()
	response = res.json()
	print(response)
	assert not response["error"]
	assert not Path(f"/var/lib/opsi/depot/{TESTPACKAGE_NAME}").exists()


def test_jsonrpc_create_files(test_client: OpsiconfdTestClient, tmp_path: Path) -> None:  # noqa: F811
	res = test_client.post(
		"/rpc",
		auth=(ADMIN_USER, ADMIN_PASS),
		json={"id": 1, "method": "depot_createMd5SumFile", "params": [str(TESTPACKAGE), str(tmp_path / "md5file")]},
	)
	res.raise_for_status()
	response = res.json()
	assert not response["error"]
	assert (tmp_path / "md5file").exists()
	res = test_client.post(
		"/rpc",
		auth=(ADMIN_USER, ADMIN_PASS),
		json={"id": 1, "method": "depot_createZsyncFile", "params": [str(TESTPACKAGE), str(tmp_path / "zsyncfile")]},
	)
	res.raise_for_status()
	response = res.json()
	assert not response["error"]
	assert (tmp_path / "zsyncfile").exists()


def test_jsonrpc_rsync(test_client: OpsiconfdTestClient, tmp_path: Path) -> None:  # noqa: F811
	res = test_client.post(
		"/rpc",
		auth=(ADMIN_USER, ADMIN_PASS),
		json={"id": 1, "method": "depot_librsyncSignature", "params": [str(TESTFILE)]},
	)
	res.raise_for_status()
	response = res.json()
	assert not response["error"]
	signature = response["result"]

	res = test_client.post(
		"/rpc",
		auth=(ADMIN_USER, ADMIN_PASS),
		json={"id": 1, "method": "depot_librsyncDeltaFile", "params": [str(TESTFILE), signature, str(tmp_path / "deltafile")]},
	)
	res.raise_for_status()
	response = res.json()
	assert not response["error"]
	assert (tmp_path / "deltafile").exists()
	print((tmp_path / "deltafile").read_bytes())

	res = test_client.post(
		"/rpc",
		auth=(ADMIN_USER, ADMIN_PASS),
		json={
			"id": 1,
			"method": "depot_librsyncPatchFile",
			"params": [str(TESTFILE), str(tmp_path / "deltafile"), str(tmp_path / "result")],
		},
	)
	res.raise_for_status()
	response = res.json()
	assert not response["error"]
	assert (tmp_path / "result").exists()
	assert (tmp_path / "result").read_text() == "test\n"


def test_jsonrpc_workbench(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	workbench_path = tmp_path / "workbench"
	depot_path = tmp_path / "depot"
	with (
		patch("opsiconfd.backend.rpc.depot.WORKBENCH_DIR", str(workbench_path)),
		patch("opsiconfd.backend.rpc.depot.DEPOT_DIR", str(depot_path)),
	):
		package_dir = workbench_path / "testpackage"
		Path(package_dir / "CLIENT_DATA").mkdir(parents=True, exist_ok=True)
		Path(package_dir / "CLIENT_DATA" / "test.file").write_bytes(b"opsi")
		Path(package_dir / "OPSI").mkdir(exist_ok=True)
		shutil.copy(CONTROLFILE, Path(package_dir / "OPSI"))
		res = test_client.post(
			"/rpc",
			auth=(ADMIN_USER, ADMIN_PASS),
			json={"jsonrpc": "2.0", "id": 1, "method": "workbench_buildPackage", "params": [str(package_dir)]},
		)
		res.raise_for_status()
		response = res.json()
		assert "error" not in response
		assert (package_dir / "localboot_new_42.0-1337.opsi").exists()

		res = test_client.post(
			"/rpc",
			auth=(ADMIN_USER, ADMIN_PASS),
			json={"jsonrpc": "2.0", "id": 1, "method": "workbench_installPackage", "params": [str(package_dir)]},
		)
		res.raise_for_status()
		response = res.json()
		assert "error" not in response
		assert (depot_path / "localboot_new").exists()
