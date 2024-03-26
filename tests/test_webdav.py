# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
webdav tests
"""
import os
import random
import shutil
from pathlib import Path
from string import ascii_letters
from threading import Event, Lock, Thread
from typing import BinaryIO, Type
from unittest.mock import patch

import psutil
import pytest
from pyzsync import (
	CaseInsensitiveDict,
	HTTPPatcher,
	Patcher,
	PatchInstruction,
	create_zsync_file,
	get_patch_instructions,
	patch_file,
	read_zsync_file,
)

from opsiconfd.application.webdav import IgnoreCaseFilesystemProvider, webdav_setup
from opsiconfd.config import get_depotserver_id

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	UnprotectedBackend,
	app,
	backend,
	clean_mysql,
	clean_redis,
	config,
	test_client,
)


def test_webdav_setup() -> None:
	webdav_setup(app)


def test_options_request_for_index(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	# Windows WebDAV client send OPTIONS request for /
	res = test_client.request(method="OPTIONS", url="/")
	assert res.status_code == 200
	assert res.headers["Allow"] == "OPTIONS, GET, HEAD"


def test_webdav_path_modification(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	res = test_client.request(method="PROPFIND", url="/dav", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 207


def test_webdav_upload_download_delete_with_special_chars(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	size = 1 * 1024 * 1024
	rand_bytes = ("".join(random.choice(ascii_letters) for i in range(size))).encode("ascii")
	headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}
	filename = "陰陽_üß.bin"

	url = f"/repository/{filename}"
	res = test_client.put(url=url, headers=headers, content=rand_bytes)
	res.raise_for_status()

	assert os.path.exists(os.path.join("/var/lib/opsi/repository", filename))

	res = test_client.get(url=url)
	res.raise_for_status()
	assert rand_bytes == res.content

	res = test_client.delete(url=url)
	res.raise_for_status()


def test_webdav_auth(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	url = "/repository/test_file.bin"
	res = test_client.get(url=url)
	assert res.status_code == 401


def test_client_permission(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	client_id = "webdavtest.uib.local"
	client_key = "af521906af3c4666bed30a1774639ff8"
	rpc = {"id": 1, "method": "host_createOpsiClient", "params": [client_id, client_key]}
	resp = test_client.post("/rpc", json=rpc, auth=(ADMIN_USER, ADMIN_PASS))
	assert resp.status_code == 200
	res = resp.json()
	assert res.get("error") is None
	test_client.reset_cookies()

	size = 1024
	data = ("".join(random.choice(ascii_letters) for i in range(size))).encode("ascii")
	headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}
	for path in ("workbench", "repository", "depot"):
		url = f"/{path}/test_file_client.bin"

		res = test_client.put(url=url, content=data, headers=headers, auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code in (201, 204)
		test_client.reset_cookies()

		res = test_client.put(url=url, auth=(client_id, client_key))
		assert res.status_code == 401

		res = test_client.get(url=url, auth=(client_id, client_key))
		assert res.status_code == 200 if path == "depot" else 401

		res = test_client.delete(url=url, auth=(client_id, client_key))
		assert res.status_code == 401
		test_client.reset_cookies()

		res = test_client.delete(url=url, auth=(ADMIN_USER, ADMIN_PASS))
		assert res.status_code == 204

		test_client.post(url="/admin/unblock-all")
		test_client.reset_cookies()

	rpc = {"id": 1, "method": "host_delete", "params": [client_id]}
	res = test_client.post("/rpc", json=rpc, auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 200


@pytest.mark.parametrize(
	"filename, path, exception",
	(
		("/filename.txt", "/filename.TXT", None),
		("/outside.root", "../outside.root", RuntimeError),
		("/tEsT/TesT2/fileNaME1.TXt", "/test/test2/filename1.txt", None),
		("/Test/test/filename1.bin", "/test/test/filename1.bin", None),
		("/tEßT/TäsT2/陰陽_Üß.TXt", "/tEßT/täsT2/陰陽_üß.txt", None),
	),
)
def test_webdav_ignore_case_download(
	test_client: OpsiconfdTestClient,  # noqa: F811
	filename: str,
	path: str,
	exception: Type[Exception],
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	base_dir = "/var/lib/opsi/depot"
	directory, filename = filename.rsplit("/", 1)
	directory = directory.strip("/")
	abs_dir = os.path.join(base_dir, directory)
	abs_filename = os.path.join(abs_dir, filename)

	prov = IgnoreCaseFilesystemProvider(base_dir)

	if directory:
		os.makedirs(abs_dir)
	try:
		with open(abs_filename, "w", encoding="utf-8") as file:
			file.write(filename)

		if exception:
			with pytest.raises(exception):
				prov._loc_to_file_path(path)
		else:
			file_path = prov._loc_to_file_path(path)
			assert file_path == f"{base_dir}/{directory + '/' if directory else ''}{filename}"

		url = f"/depot/{path}"
		res = test_client.get(url=url)
		if exception:
			assert res.status_code == 404
		else:
			res.raise_for_status()
			assert res.content.decode("utf-8") == filename
	finally:
		if directory:
			shutil.rmtree(os.path.join(base_dir, directory.split("/")[0]))
		else:
			os.unlink(abs_filename)


def test_webdav_symlink(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	base_dir = Path("/var/lib/opsi/depot/symlink_test")
	base_dir.mkdir(parents=True)
	try:
		test_dir = Path(base_dir / "testdir")
		test_dir.mkdir()
		test_file = Path(test_dir / "testfile.txt")
		test_file.write_bytes(b"opsi")
		Path(base_dir / "test_link_file").symlink_to(test_file)
		Path(base_dir / "test_link_dir").symlink_to(test_dir)
		for path in (
			"/depot/symlink_test/testdir/testfile.txt",
			"/depot/symlink_test/test_link_file",
			"/depot/symlink_test/test_link_dir/testfile.txt",
			"/dav/depot/symlink_test/testdir/testfile.txt",
			"/dav/depot/symlink_test/test_link_file",
			"/dav/depot/symlink_test/test_link_dir/testfile.txt",
		):
			res = test_client.get(url=path)
			res.raise_for_status()
			assert res.content == b"opsi"
	finally:
		if base_dir.exists():
			shutil.rmtree(base_dir)


def test_webdav_virtual_folder(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	res = test_client.get(url="/dav")
	assert res.status_code == 200

	assert "/boot" in res.text
	assert "/depot" in res.text
	assert "/public" in res.text
	assert "/repository" in res.text
	assert "/workbench" in res.text


def test_webdav_setup_exception(backend: UnprotectedBackend) -> None:  # noqa: F811
	host = backend.host_getObjects(type="OpsiDepotserver", id=get_depotserver_id())[0]
	repo_url = host.getRepositoryLocalUrl()
	depot_url = host.getDepotLocalUrl()
	workbench_url = host.getWorkbenchLocalUrl()
	with patch("opsiconfd.application.webdav.PUBLIC_DIR", "/file/not/found"):
		try:
			host.setRepositoryLocalUrl("file:///not/found")
			host.setDepotLocalUrl("file:///not/found")
			host.setWorkbenchLocalUrl("file:///not/found")
			webdav_setup(app)
		finally:
			host.setRepositoryLocalUrl(repo_url)
			host.setDepotLocalUrl(depot_url)
			host.setWorkbenchLocalUrl(workbench_url)


class MemoryUsageWatcher(Thread):
	def __init__(self) -> None:
		super().__init__(daemon=True)
		self.process = psutil.Process()
		self.stop = Event()
		self.lock = Lock()
		self.memory_usage: list[int] = []

	def avg_mem(self) -> float:
		with self.lock:
			return sum(self.memory_usage) / len(self.memory_usage)

	def max_mem(self) -> float:
		with self.lock:
			return max(self.memory_usage)

	def cur_mem(self) -> float:
		with self.lock:
			return self.memory_usage[-1]

	def clear(self) -> None:
		with self.lock:
			self.memory_usage = []

	def run(self) -> None:
		while not self.stop.wait(0.1):
			with self.lock:
				self.memory_usage.append(self.process.memory_info().rss)


def test_repository_zsync(test_client: OpsiconfdTestClient, tmp_path: Path) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	class TestHTTPPatcher(HTTPPatcher):
		test_client: OpsiconfdTestClient

		def _send_request(self) -> tuple[int, CaseInsensitiveDict]:
			self._response = self.test_client.request("GET", self._url.path, headers=self._headers)
			return self._response.status_code, CaseInsensitiveDict(dict(self._response.headers))

		def _read_response_data(self, size: int | None = None) -> bytes:
			if not size:
				size = len(self._response._content)
			data = self._response._content[:size]
			self._response._content = self._response._content[size:]
			return data

	remote_file = Path("/var/lib/opsi/repository/remote")
	remote_zsync_file = Path("/var/lib/opsi/repository/remote.zsync")
	local_file = tmp_path / "local"
	local_file_bak = tmp_path / "local.bak"

	block_count = 10
	block_size = 2048
	with open(remote_file, "wb") as rfile, open(local_file, "wb") as lfile:
		for block_id in range(block_count):
			block_data = random.randbytes(int(block_size / 2) if block_id == block_count - 1 else block_size)
			rfile.write(block_data)
			if block_id in (1, 2, 3, 7):
				lfile.write(block_data)

	shutil.copy(local_file, local_file_bak)
	create_zsync_file(remote_file, remote_zsync_file, legacy_mode=False)
	zsync_info = read_zsync_file(remote_zsync_file)
	zsync_info.seq_matches = 1
	instructions = get_patch_instructions(zsync_info, local_file)

	http_patcher: HTTPPatcher | None = None

	def patcher_factory(instructions: list[PatchInstruction], target_file: BinaryIO) -> Patcher:
		nonlocal http_patcher
		http_patcher = TestHTTPPatcher(
			instructions=instructions, target_file=target_file, url="https://localhost:4447/repository/remote", max_ranges_per_request=1
		)
		http_patcher.test_client = test_client
		return http_patcher

	sha256 = patch_file(local_file, instructions, patcher_factory, return_hash="sha256")
	assert remote_file.stat().st_size == local_file.stat().st_size
	assert sha256 == zsync_info.sha256
	assert remote_file.read_bytes() == local_file.read_bytes()
