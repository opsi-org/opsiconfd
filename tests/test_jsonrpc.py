# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
jsonrpc tests
"""

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import msgpack  # type: ignore[import]
import pytest
from opsicommon.objects import OpsiClient  # type: ignore[import]

from opsiconfd.application.jsonrpc import (
	compress_data,
	decompress_data,
	deserialize_data,
	serialize_data,
)

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	backend,
	clean_redis,
	config,
	get_config,
	get_dummy_products,
	products_jsonrpc,
	sync_redis_client,
	test_client,
)

TESTDIR = Path("tests/data/jsonrpc/test_dir")
TESTFILE = TESTDIR / "testfile"
TESTPACKAGE_NAME = "localboot_legacy"
TESTPACKAGE = Path(f"tests/data/jsonrpc/{TESTPACKAGE_NAME}_42.0-1337.opsi")
CONTROLFILE = Path("tests/data/jsonrpc/control")


def test_request_param_list(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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


def test_request_param_dict(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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


def test_multi_request(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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


def test_incomplete_request(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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


def test_jsonrpc20(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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
		(None, None, "application/json"),
		("", "", "application/json"),
		("", "msgpack", "application/msgpack"),
		("msgpack", "xyasdb;dsaoswe3dod", "application/msgpack"),
		("invalid", "application/msgpack", "application/msgpack"),
	),
)
def test_serializations(
	test_client: OpsiconfdTestClient, content_type: str, accept: str, expected_content_type: str  # pylint: disable=redefined-outer-name
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
	test_client: OpsiconfdTestClient, content_encoding: str, accept_encoding: str, status_code: int  # pylint: disable=redefined-outer-name
) -> None:
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
			data = decompress_data(data, accept_encoding)
		assert deserialize_data(data, "json")


def test_error_log(test_client: OpsiconfdTestClient, tmp_path: Path) -> None:  # pylint: disable=redefined-outer-name
	with (patch("opsiconfd.application.jsonrpc.RPC_DEBUG_DIR", str(tmp_path)), get_config({"debug_options": "rpc-error-log"})):
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


def test_store_rpc_info(config: Config, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	with sync_redis_client() as redis:
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


def test_jsonrpc_depotservermixin(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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


def test_jsonrpc_package_install(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	res = test_client.post(
		"/rpc", auth=(ADMIN_USER, ADMIN_PASS), json={"id": 1, "method": "depot_installPackage", "params": [str(TESTPACKAGE)]}
	)
	res.raise_for_status()
	response = res.json()
	assert not response["error"]
	assert Path(f"/var/lib/opsi/depot/{TESTPACKAGE_NAME}").exists()
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


def test_jsonrpc_create_files(test_client: OpsiconfdTestClient, tmp_path: Path) -> None:  # pylint: disable=redefined-outer-name
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


def test_jsonrpc_rsync(test_client: OpsiconfdTestClient, tmp_path: Path) -> None:  # pylint: disable=redefined-outer-name
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


def test_jsonrpc_workbench(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	package_dir = Path("/var/lib/opsi/workbench/testpackage")
	Path(package_dir / "CLIENT_DATA").mkdir(parents=True, exist_ok=True)
	Path(package_dir / "OPSI").mkdir(exist_ok=True)
	shutil.copy(CONTROLFILE, Path(package_dir / "OPSI"))
	res = test_client.post(
		"/rpc",
		auth=(ADMIN_USER, ADMIN_PASS),
		json={"id": 1, "method": "workbench_buildPackage", "params": [str(package_dir)]},
	)
	res.raise_for_status()
	response = res.json()
	if response["error"]:
		assert "Zstd not available" in response["error"]["message"]
	else:
		assert (package_dir / "localboot_new_42.0-1337.opsi").exists()

	res = test_client.post(
		"/rpc",
		auth=(ADMIN_USER, ADMIN_PASS),
		json={"id": 1, "method": "workbench_installPackage", "params": [str(package_dir)]},
	)
	res.raise_for_status()
	response = res.json()
	if response["error"]:
		assert "Zstd not available" in response["error"]["message"]
	else:
		assert Path("/var/lib/opsi/depot/localboot_new").exists()
