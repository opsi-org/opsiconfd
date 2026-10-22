# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test application.filetransfer
"""

from collections.abc import Generator
from pathlib import Path
from time import sleep, time
from unittest.mock import patch

import pytest
from msgspec import json
from opsi.opsi.service.model.object import OpsiClient
from werkzeug.http import parse_options_header

from opsiconfd.application.filetransfer import _prepare_file, cleanup_file_storage

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	get_config,
	test_client,
)


def test_raw_file_upload_download_delete(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with patch("opsiconfd.application.filetransfer.FILE_TRANSFER_STORAGE_DIR", str(tmp_path)):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		data = b"file-data"
		resp = test_client.post("/file-transfer/raw", content=data)
		assert resp.status_code == 201
		file_id = resp.json()["file_id"]
		assert file_id
		file_path = tmp_path / file_id
		meta_path = file_path.with_suffix(".meta")
		assert file_path.read_bytes() == data
		meta = json.decode(meta_path.read_bytes())
		assert abs(time() - meta["created"]) < 10

		resp = test_client.get(f"/file-transfer/{file_id}")
		assert resp.status_code == 200
		assert resp.content == data

		resp = test_client.delete(f"/file-transfer/{file_id}")
		assert resp.status_code == 200
		assert resp.json()["file_id"] == file_id

		assert not file_path.exists()
		assert not meta_path.exists()


def test_raw_file_upload_download_with_delete(
	tmp_path: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client = OpsiClient(id="test-file-upload-1.opsi.org")
	client.setDefaults()
	assert client.opsiHostKey
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	test_client.reset_cookies()
	test_client.auth = (client.id, client.opsiHostKey)

	with patch("opsiconfd.application.filetransfer.FILE_TRANSFER_STORAGE_DIR", str(tmp_path)):
		data = b"file-data"
		resp = test_client.post("/file-transfer/raw", content=data)
		assert resp.status_code == 201
		file_id = resp.json()["file_id"]
		assert file_id
		file_path = tmp_path / file_id
		meta_path = file_path.with_suffix(".meta")
		assert file_path.read_bytes() == data
		meta = json.decode(meta_path.read_bytes())
		assert abs(time() - meta["created"]) < 10

		resp = test_client.get(f"/file-transfer/{file_id}", params={"delete": "false"})
		assert resp.status_code == 200
		assert resp.content == data
		assert file_path.exists()
		assert meta_path.exists()

		resp = test_client.get(f"/file-transfer/{file_id}", params={"delete": "true"})
		assert resp.status_code == 200
		assert resp.content == data
		assert not file_path.exists()
		assert not meta_path.exists()


def test_file_access_only_by_owner_and_admin(
	tmp_path: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	clients = [OpsiClient(id="test-file-access-1.opsi.org"), OpsiClient(id="test-file-access-2.opsi.org")]
	for client in clients:
		client.setDefaults()
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[c.to_hash() for c in clients]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	def login(username: str, password: str) -> None:
		"""Start a new session for the given user."""
		test_client.reset_cookies()
		test_client.auth = (username, password)

	with patch("opsiconfd.application.filetransfer.FILE_TRANSFER_STORAGE_DIR", str(tmp_path)):
		data = b"file-data"
		login(clients[0].id, str(clients[0].opsiHostKey))
		resp = test_client.post("/file-transfer/raw", content=data)
		assert resp.status_code == 201
		file_id = resp.json()["file_id"]

		# Other client is not allowed to access the file
		login(clients[1].id, str(clients[1].opsiHostKey))
		resp = test_client.get(f"/file-transfer/{file_id}")
		assert resp.status_code == 403
		resp = test_client.get(f"/file-transfer/{file_id}", params={"delete": "true"})
		assert resp.status_code == 403
		resp = test_client.delete(f"/file-transfer/{file_id}")
		assert resp.status_code == 403
		assert (tmp_path / file_id).exists()

		# Owner and admin are allowed to access the file
		login(clients[0].id, str(clients[0].opsiHostKey))
		resp = test_client.get(f"/file-transfer/{file_id}")
		assert resp.status_code == 200
		assert resp.content == data

		login(ADMIN_USER, ADMIN_PASS)
		resp = test_client.get(f"/file-transfer/{file_id}")
		assert resp.status_code == 200
		assert resp.content == data
		resp = test_client.delete(f"/file-transfer/{file_id}")
		assert resp.status_code == 200
		assert not (tmp_path / file_id).exists()


def test_multipart_file_upload_download_delete(
	tmp_path: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	with patch("opsiconfd.application.filetransfer.FILE_TRANSFER_STORAGE_DIR", str(tmp_path)):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		data = b"file-data"
		filename = "testäöü.txt"
		content_type = "text/plain"

		files = {"file": (filename, data, content_type)}

		res = test_client.post("/file-transfer/multipart", files=files)
		assert res.status_code == 201
		file_id = res.json()["file_id"]
		assert file_id
		file_path = tmp_path / file_id
		meta_path = file_path.with_suffix(".meta")
		assert file_path.read_bytes() == data
		meta = json.decode(meta_path.read_bytes())
		assert abs(time() - meta["created"]) < 10
		assert meta["filename"] == filename
		assert meta["content_type"] == content_type

		res = test_client.get(f"/file-transfer/{file_id}")
		assert res.status_code == 200
		assert res.content == data

		assert res.headers["content-type"].split(";")[0] == content_type
		assert parse_options_header(res.headers["content-disposition"])[1]["filename"] == filename

		res = test_client.delete(f"/file-transfer/{file_id}")
		assert res.status_code == 200
		assert res.json()["file_id"] == file_id

		assert not file_path.exists()
		assert not meta_path.exists()


def test_cleanup_file_storage(tmp_path: Path) -> None:
	with patch("opsiconfd.application.filetransfer.FILE_TRANSFER_STORAGE_DIR", str(tmp_path)):
		(tmp_path / "invalid").touch()
		(tmp_path / "invalid.meta").touch()
		(tmp_path / ".hidden").touch()
		(tmp_path / "subdir").mkdir()
		(tmp_path / "invalid2.meta").write_bytes(b"-")
		path = _prepare_file("test").file_path
		path.rename(path.parent / "invalid-uuid-filename")
		path.with_suffix(".meta").rename(path.parent / "invalid-uuid-filename.meta")
		_prepare_file("expired", validity=1)  # Valid for 1 second
		sleep(2)

		valid_files = [_prepare_file("ok").file_path, _prepare_file("ok").file_path, _prepare_file("ok").file_path]
		valid_meta = [f.with_suffix(".meta") for f in valid_files]
		valid_filenames = [f.name for f in valid_files + valid_meta]

		cleanup_file_storage()

		for path in tmp_path.iterdir():
			if not path.is_file():
				continue
			assert path.name in valid_filenames


def test_raw_file_stream_upload(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	with patch("opsiconfd.application.filetransfer.FILE_TRANSFER_STORAGE_DIR", str(tmp_path)):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		blocksize = 1024
		chunks = 10

		def read_chunks() -> Generator[bytes]:
			for chunk in range(chunks):
				yield chunk.to_bytes() * blocksize

		resp = test_client.post("/file-transfer/raw", content=read_chunks())
		assert resp.status_code == 201
		file_id = resp.json()["file_id"]
		assert file_id
		try:
			file_path = tmp_path / file_id
			file_data = file_path.read_bytes()
			assert len(file_data) == chunks * blocksize

			data = b""
			with test_client.stream("GET", f"/file-transfer/{file_id}") as resp:
				for chunk in resp.iter_raw(blocksize):
					data += chunk

			assert resp.status_code == 200
			assert data == file_data
		finally:
			resp = test_client.delete(f"/file-transfer/{file_id}")
			assert resp.status_code == 200
			assert resp.json()["file_id"] == file_id


@pytest.mark.parametrize("upload_type", ("raw", "raw-stream", "multipart"))
@pytest.mark.parametrize("size_diff, expected_status_code", ((0, 201), (1, 413)))
def test_file_upload_max_size(
	tmp_path: Path,
	test_client: OpsiconfdTestClient,  # noqa: F811
	upload_type: str,
	size_diff: int,
	expected_status_code: int,
) -> None:
	max_size = 1024 * 1024
	data = b"x" * (max_size + size_diff)

	def read_chunks() -> Generator[bytes]:
		"""Stream the data without content-length header."""
		for idx in range(0, len(data), 100_000):
			yield data[idx : idx + 100_000]

	with (
		patch("opsiconfd.application.filetransfer.FILE_TRANSFER_STORAGE_DIR", str(tmp_path)),
		get_config({"file_transfer_max_size": 1}),
	):
		test_client.auth = (ADMIN_USER, ADMIN_PASS)
		if upload_type == "raw":
			resp = test_client.post("/file-transfer/raw", content=data)
		elif upload_type == "raw-stream":
			resp = test_client.post("/file-transfer/raw", content=read_chunks())
		else:
			resp = test_client.post("/file-transfer/multipart", files={"file": ("test.bin", data, "application/octet-stream")})

		assert resp.status_code == expected_status_code
		if expected_status_code == 201:
			assert (tmp_path / resp.json()["file_id"]).read_bytes() == data
		else:
			assert "maximum size" in resp.json()["error"]
			# File and metadata must be removed
			assert not list(tmp_path.iterdir())
