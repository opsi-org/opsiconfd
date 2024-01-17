# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav tests
"""
import gc
import os
import random
import shutil
import time
from pathlib import Path
from string import ascii_letters
from threading import Event, Lock, Thread
from typing import Generator, Type
from unittest.mock import patch

import psutil
import pytest

from opsiconfd.application.main import app
from opsiconfd.application.webdav import IgnoreCaseFilesystemProvider, webdav_setup
from opsiconfd.config import get_depotserver_id

from .utils import (  # pylint: disable=unused-import
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


def test_options_request_for_index(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	# Windows WebDAV client send OPTIONS request for /
	res = test_client.request(method="OPTIONS", url="/")
	assert res.status_code == 200
	assert res.headers["Allow"] == "OPTIONS, GET, HEAD"


def test_webdav_path_modification(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	res = test_client.request(method="PROPFIND", url="/dav", auth=(ADMIN_USER, ADMIN_PASS))
	assert res.status_code == 207


def test_webdav_upload_download_delete_with_special_chars(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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


def test_webdav_auth(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	url = "/repository/test_file.bin"
	res = test_client.get(url=url)
	assert res.status_code == 401


def test_client_permission(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
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
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name
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
				prov._loc_to_file_path(path)  # pylint: disable=protected-access
		else:
			file_path = prov._loc_to_file_path(path)  # pylint: disable=protected-access
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
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name
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


def test_webdav_virtual_folder(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	res = test_client.get(url="/dav")
	assert res.status_code == 200

	assert "/boot" in res.text
	assert "/depot" in res.text
	assert "/public" in res.text
	assert "/repository" in res.text
	assert "/workbench" in res.text


def test_webdav_setup_exception(backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	host = backend.host_getObjects(type="OpsiDepotserver", id=get_depotserver_id())[0]  # pylint: disable=no-member
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


def test_webdav_memory_consumption(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	mem_watch = MemoryUsageWatcher()
	mem_watch.start()
	try:
		size = 100_000_000
		chunk_size = 100_000

		headers = {"Content-Type": "binary/octet-stream", "Content-Length": str(size)}
		filename = "test_data.bin"

		def get_data() -> Generator[bytes, None, None]:
			chunks = int(size / chunk_size)
			for _ in range(chunks):
				time.sleep(10.0 / chunks)
				yield b"d" * chunk_size

		gc.collect()
		time.sleep(1)
		mem_watch.clear()
		time.sleep(1)
		cur_mem = mem_watch.cur_mem()

		url = f"/repository/{filename}"
		res = test_client.put(url=url, headers=headers, content=get_data())
		res.raise_for_status()
		max_mem = mem_watch.max_mem()
		usage_max_upload = max_mem - cur_mem

		assert os.path.exists(os.path.join("/var/lib/opsi/repository", filename))

		gc.collect()
		time.sleep(1)
		mem_watch.clear()
		time.sleep(1)
		cur_mem = mem_watch.cur_mem()

		with test_client.stream(method="GET", url=url) as res:
			chunks = int(size / chunk_size)
			for _ in res.iter_raw(chunk_size=chunk_size):
				time.sleep(10.0 / chunks)

		res.raise_for_status()

		max_mem = mem_watch.max_mem()
		usage_max_download = max_mem - cur_mem

		res = test_client.delete(url=url)
		res.raise_for_status()

		print(f"Max memory usage upload: {usage_max_upload / 1_000_000:.2f} MB")
		print(f"Max memory usage download: {usage_max_download / 1_000_000:.2f} MB")

		assert usage_max_upload < size * 1.5
		assert usage_max_download < size * 2.5
	finally:
		mem_watch.stop.set()
